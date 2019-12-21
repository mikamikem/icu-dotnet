// Copyright (c) 2013-2017 SIL International
// This software is licensed under the MIT license (http://opensource.org/licenses/MIT)
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Icu
{
	internal static partial class NativeMethods
	{
		private static readonly object _lock = new object();

		internal static int MinIcuVersion { get; private set; } = Wrapper.MinSupportedIcuVersion;
		internal static int MaxIcuVersion { get; private set; } = Wrapper.MaxSupportedIcuVersion;

		public static void SetMinMaxIcuVersions(int minVersion = Wrapper.MinSupportedIcuVersion,
			int maxVersion = Wrapper.MaxSupportedIcuVersion)
		{
			if (minVersion < Wrapper.MinSupportedIcuVersion || minVersion > Wrapper.MaxSupportedIcuVersion)
			{
				throw new ArgumentOutOfRangeException(nameof(minVersion),
					$"supported ICU versions are between {Wrapper.MinSupportedIcuVersion} and {Wrapper.MaxSupportedIcuVersion}");
			}
			if (maxVersion < Wrapper.MinSupportedIcuVersion || maxVersion > Wrapper.MaxSupportedIcuVersion)
			{
				throw new ArgumentOutOfRangeException(nameof(maxVersion),
					$"supported ICU versions are between {Wrapper.MinSupportedIcuVersion} and {Wrapper.MaxSupportedIcuVersion}");
			}

			lock (_lock)
			{
				MinIcuVersion = Math.Min(minVersion, maxVersion);
				MaxIcuVersion = Math.Max(minVersion, maxVersion);
			}

			if (!IsInitialized)
				return;

			Cleanup();
			Wrapper.Init();
		}

		private static MethodsContainer Methods;

		static NativeMethods()
		{
			Methods = new MethodsContainer();
			ResetIcuVersionInfo();
		}

		#region Dynamic method loading

		#region Native methods for Linux

		private const int RTLD_NOW = 2;

		private const string LIBDL_NAME = "libdl.so.2";

		[DllImport(LIBDL_NAME, SetLastError = true)]
		private static extern IntPtr dlopen(string file, int mode);

		[DllImport(LIBDL_NAME, SetLastError = true)]
		private static extern int dlclose(IntPtr handle);

		[DllImport(LIBDL_NAME, SetLastError = true)]
		private static extern IntPtr dlsym(IntPtr handle, string name);

		[DllImport(LIBDL_NAME, EntryPoint = "dlerror")]
		private static extern IntPtr _dlerror();

		private static string dlerror()
		{
			// Don't free the string returned from _dlerror()!
			var ptr = _dlerror();
			return Marshal.PtrToStringAnsi(ptr);
		}

		#endregion

		#region Native methods for macOS

		private const string macOSicu4cBrewPath = "/usr/local/Cellar/icu4c/";

		private const string MACOS_LIBDL_NAME = "dl";

		[DllImport(MACOS_LIBDL_NAME, EntryPoint = "dlopen", SetLastError = true)]
		private static extern IntPtr macOS_dlopen(string file, int mode);

		[DllImport(MACOS_LIBDL_NAME, EntryPoint = "dlclose", SetLastError = true)]
		private static extern int macOS_dlclose(IntPtr handle);

		[DllImport(MACOS_LIBDL_NAME, EntryPoint = "dlsym", SetLastError = true)]
		private static extern IntPtr macOS_dlsym(IntPtr handle, string name);

		[DllImport(MACOS_LIBDL_NAME, EntryPoint = "dlerror")]
		private static extern IntPtr _macOS_dlerror();

		private static string macOS_dlerror()
		{
			// Don't free the string returned from _dlerror()!
			var ptr = _macOS_dlerror();
			return Marshal.PtrToStringAnsi(ptr);
		}

		#endregion

		#region Native methods for Windows

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr LoadLibraryEx(string dllToLoad, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool FreeLibrary(IntPtr hModule);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

		[Flags]
		private enum LoadLibraryFlags : uint
		{
			NONE = 0x00000000,
			DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
			LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
			LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
			LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
			LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
			LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
			LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
			LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
			LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
			LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
			LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
		}

		#endregion

		private static int IcuVersion;
		private static string _IcuPath;
		private static IntPtr _IcuCommonLibHandle;
		private static IntPtr _IcuI18NLibHandle;

		private static IntPtr IcuCommonLibHandle
		{
			get
			{
				if (_IcuCommonLibHandle == IntPtr.Zero)
					_IcuCommonLibHandle = LoadIcuLibrary("icuuc");
				return _IcuCommonLibHandle;
			}
		}

		private static IntPtr IcuI18NLibHandle
		{
			get
			{
				if(_IcuI18NLibHandle == IntPtr.Zero)
				{
					string i18nlibName = "";

					switch(Platform.OperatingSystem)
					{
						case OperatingSystemType.Windows:
							i18nlibName = "icuin";
							break;
						case OperatingSystemType.Unix:
							i18nlibName = "icui18n";
							break;
						case OperatingSystemType.MacOSX:
							i18nlibName = "icui18n";
							break;
					}

					_IcuI18NLibHandle = LoadIcuLibrary(i18nlibName);
				}

				return _IcuI18NLibHandle;
			}
		}

		internal static string DirectoryOfThisAssembly
		{
			get
			{
				//NOTE: .GetTypeInfo() is not supported until .NET 4.5 onwards.
#if NET40
				Assembly currentAssembly = typeof(NativeMethods).Assembly;
#else
				Assembly currentAssembly = typeof(NativeMethods).GetTypeInfo().Assembly;
#endif
				var managedPath = currentAssembly.CodeBase ?? currentAssembly.Location;
				var uri = new Uri(managedPath);

				return Path.GetDirectoryName(uri.LocalPath);
			}
		}

		private static bool IsRunning64Bit => Platform.ProcessArchitecture == Platform.x64;

		private static bool IsInitialized { get; set; }

		private static void AddDirectoryToSearchPath(string directory)
		{
			// Only perform this for non-Windows because we are using LoadLibraryEx
			// to ensure that a library's dependencies is loaded starting from
			// where that library is located.
			if (Platform.OperatingSystem != OperatingSystemType.Windows)
			{
				var ldLibPath = Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
				Environment.SetEnvironmentVariable("LD_LIBRARY_PATH",
					$"{directory}:{ldLibPath}");
			}
		}

		private static bool CheckDirectoryForIcuBinaries(string directory, string libraryName)
		{
			if (!Directory.Exists(directory))
				return false;

			string filePattern = "";

			switch(Platform.OperatingSystem)
			{
				case OperatingSystemType.Windows:
					filePattern = libraryName + "*.dll";
					break;
				case OperatingSystemType.Unix:
					filePattern = "lib" + libraryName + ".so.*";
					break;
				case OperatingSystemType.MacOSX:
					filePattern = "lib" + libraryName + ".*.dylib";
					break;
			}

			var files = Directory.EnumerateFiles(directory, filePattern).ToList();
			if (files.Count > 0)
			{
				// Do a reverse sort so that we use the highest version
				files.Sort((x, y) => string.CompareOrdinal(y, x));
				var filePath = files[0];
				string version = "";

				switch(Platform.OperatingSystem)
				{
					case OperatingSystemType.Windows:
						version = Path.GetFileNameWithoutExtension(filePath).Substring(5);
						break;
					case OperatingSystemType.Unix:
						version = Path.GetFileName(filePath).Substring(12);
						break;
					case OperatingSystemType.MacOSX:
						version = Path.GetFileNameWithoutExtension(filePath).Replace("lib" + libraryName + ".", "").Replace(".dylib", "");
						break;
				}

				int icuVersion;
				if (int.TryParse(version, out icuVersion))
				{
					Trace.TraceInformation("Setting IcuVersion to {0} (found in {1})",
						icuVersion, directory);
					IcuVersion = icuVersion;
					_IcuPath = directory;

					AddDirectoryToSearchPath(directory);
					return true;
				}
			}
			return false;
		}

		private static bool LocateIcuLibrary(string libraryName)
		{
			var arch = IsRunning64Bit ? "x64" : "x86";
			// Look for ICU binaries in lib/{win,linux,macos}-{x86,x64} subdirectory first
			string platform = "";

			switch(Platform.OperatingSystem)
			{
				case OperatingSystemType.Windows:
					platform = "win";
					break;
				case OperatingSystemType.Unix:
					platform = "linux";
					break;
				case OperatingSystemType.MacOSX:
					platform = "macos";
					break;
			}

			if(CheckDirectoryForIcuBinaries(
				Path.Combine(DirectoryOfThisAssembly, "lib", $"{platform}-{arch}"),
				libraryName))
				return true;

			// Next look in lib/x86 or lib/x64 subdirectory
			if (CheckDirectoryForIcuBinaries(
				Path.Combine(DirectoryOfThisAssembly, "lib", arch),
				libraryName))
				return true;

			// next try just {win,linux,macos}-x86/x64 subdirectory
			if (CheckDirectoryForIcuBinaries(
				Path.Combine(DirectoryOfThisAssembly, $"{platform}-{arch}"),
				libraryName))
				return true;

			// next try just x86/x64 subdirectory
			if (CheckDirectoryForIcuBinaries(
				Path.Combine(DirectoryOfThisAssembly, arch),
				libraryName))
				return true;

			if(Platform.OperatingSystem == OperatingSystemType.MacOSX)
			{
				if(CheckMacOSPlatforms(libraryName))
					return true;
			}

			// otherwise check the current directory
			// If we don't find it here we rely on it being in the PATH somewhere...
			return CheckDirectoryForIcuBinaries(DirectoryOfThisAssembly, libraryName);
		}

		private static bool CheckMacOSPlatforms(string libraryName)
		{
			if(!Directory.Exists(macOSicu4cBrewPath))
				return false;

			var directories = Directory.EnumerateDirectories(macOSicu4cBrewPath).ToList();
			if(directories.Count > 0)
			{
				// Do a reverse sort so that we use the highest version
				directories.Sort((x, y) => string.CompareOrdinal(y, x));
				string desiredBaseVersion = directories[0];

				string libRootPath = Path.Combine(desiredBaseVersion, "lib");

				if(Directory.Exists(libRootPath))
				{
					return CheckDirectoryForIcuBinaries(libRootPath, libraryName);
				}
			}

			return false;
		}

		private static IntPtr LoadIcuLibrary(string libraryName)
		{
			//string versionString = "64.2";
			//IcuVersion = 64;
			//string fullLibraryPath = Path.Combine("/usr", "local", "Cellar", "icu4c", versionString, "lib", );
			//return NativeLibraryLoader.loadLibraryDelegate($"{libraryName}.{versionString}.dylib");

			Trace.WriteLineIf(!IsInitialized,
				"WARNING: ICU is not initialized. Please call Icu.Wrapper.Init() at the start of your application.");

			lock(_lock)
			{
				if(IcuVersion <= 0)
					LocateIcuLibrary(libraryName);

				var handle = GetIcuLibHandle(libraryName, IcuVersion > 0 ? IcuVersion : MaxIcuVersion);
				if(handle == IntPtr.Zero)
				{
					throw new FileLoadException($"Can't load ICU library (version {IcuVersion})",
						libraryName);
				}
				return handle;
			}
		}

		private static IntPtr GetIcuLibHandle(string basename, int icuVersion)
		{
			if (icuVersion < MinIcuVersion)
				return IntPtr.Zero;

			IntPtr handle = IntPtr.Zero;
			string libPath = "";
			int lastError = 0;
			OperatingSystemType operatingSystemType = Platform.OperatingSystem;

			if(operatingSystemType == OperatingSystemType.Windows)
			{
				var libName = $"{basename}{icuVersion}.dll";
				var isIcuPathSpecified = !string.IsNullOrEmpty(_IcuPath);
				libPath = isIcuPathSpecified ? Path.Combine(_IcuPath, libName) : libName;

				var loadLibraryFlags = LoadLibraryFlags.NONE;

				if (isIcuPathSpecified)
					loadLibraryFlags |= LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;

				handle = LoadLibraryEx(libPath, IntPtr.Zero, loadLibraryFlags);
				lastError = Marshal.GetLastWin32Error();

				Trace.WriteLineIf(handle == IntPtr.Zero && lastError != 0,
					$"Unable to load [{libPath}]. Error: {new Win32Exception(lastError).Message}");
			}
			else if(operatingSystemType == OperatingSystemType.Unix)
			{
				var libName = $"lib{basename}.so.{icuVersion}";
				libPath = string.IsNullOrEmpty(_IcuPath) ? libName : Path.Combine(_IcuPath, libName);

				handle = dlopen(libPath, RTLD_NOW);
				lastError = Marshal.GetLastWin32Error();

				Trace.WriteLineIf(handle == IntPtr.Zero && lastError != 0,
					$"Unable to load [{libPath}]. Error: {lastError} ({dlerror()})");
			}
			else if(operatingSystemType == OperatingSystemType.MacOSX)
			{
				var libName = $"lib{basename}.{icuVersion}.dylib";
				libPath = string.IsNullOrEmpty(_IcuPath) ? libName : Path.Combine(_IcuPath, libName);

				handle = macOS_dlopen(libPath, RTLD_NOW);
				lastError = Marshal.GetLastWin32Error();

				Trace.WriteLineIf(handle == IntPtr.Zero && lastError != 0,
					$"Unable to load [{libPath}]. Error: {lastError} ({macOS_dlerror()})");
			}

			if (handle == IntPtr.Zero)
			{
				Trace.TraceWarning("{0} of {1} failed with error {2}",
					operatingSystemType == OperatingSystemType.Windows ? "LoadLibraryEx" : "dlopen",
					libPath, lastError);
				return GetIcuLibHandle(basename, icuVersion - 1);
			}

			IcuVersion = icuVersion;
			return handle;
		}

		public static void Cleanup()
		{
			lock (_lock)
			{
				try
				{
					u_cleanup();
				}
				catch
				{
					// ignore failures - can happen when running unit tests
				}

				OperatingSystemType operatingSystemType = Platform.OperatingSystem;
				if(operatingSystemType == OperatingSystemType.Windows)
				{
					if (_IcuCommonLibHandle != IntPtr.Zero)
						FreeLibrary(_IcuCommonLibHandle);
					if (_IcuI18NLibHandle != IntPtr.Zero)
						FreeLibrary(_IcuI18NLibHandle);
				}
				else if(operatingSystemType == OperatingSystemType.Unix)
				{
					if(_IcuCommonLibHandle != IntPtr.Zero)
						dlclose(_IcuCommonLibHandle);
					if(_IcuI18NLibHandle != IntPtr.Zero)
						dlclose(_IcuI18NLibHandle);
				}
				else if(operatingSystemType == OperatingSystemType.MacOSX)
				{
					if(_IcuCommonLibHandle != IntPtr.Zero)
						macOS_dlclose(_IcuCommonLibHandle);
					if(_IcuI18NLibHandle != IntPtr.Zero)
						macOS_dlclose(_IcuI18NLibHandle);
				}
				_IcuCommonLibHandle = IntPtr.Zero;
				_IcuI18NLibHandle = IntPtr.Zero;

				Methods = new MethodsContainer();
				_BiDiMethods = null;
				_BreakIteratorMethods = null;
				_CodepageConversionMethods = null;
				_CollatorMethods = null;
				_LocalesMethods = null;
				_MessageFormatMethods = null;
				_NormalizeMethods = null;
				_RegexMethods = null;
				_ResourceBundleMethods = null;
				_TransliteratorMethods = null;
				_UnicodeSetMethods = null;
				ResetIcuVersionInfo();
			}
		}

		private static void ResetIcuVersionInfo()
		{
			IcuVersion = 0;
			_IcuPath = null;

#if !NET40
			NativeMethodsHelper.Reset();
			var icuInfo = NativeMethodsHelper.GetIcuVersionInfoForNetCoreOrWindows();

			if (icuInfo.Success)
			{
				_IcuPath = icuInfo.IcuPath.FullName;
				IcuVersion = icuInfo.IcuVersion;
			}
#endif
		}

		// This method is thread-safe and idempotent
		private static T GetMethod<T>(IntPtr handle, string methodName, bool missingInMinimal = false) where T : class
		{
			var versionedMethodName = $"{methodName}_{IcuVersion}";
			IntPtr methodPointer = IntPtr.Zero;

			OperatingSystemType operatingSystemType = Platform.OperatingSystem;

			if(operatingSystemType == OperatingSystemType.Windows)
			{
				methodPointer = GetProcAddress(handle, versionedMethodName);
			}
			else if(operatingSystemType == OperatingSystemType.Unix)
			{
				methodPointer = dlsym(handle, versionedMethodName);
			}
			else if(operatingSystemType == OperatingSystemType.MacOSX)
			{
				methodPointer = macOS_dlsym(handle, versionedMethodName);
			}

			// Some systems (eg. Tizen) don't use methods with IcuVersion suffix
			if (methodPointer == IntPtr.Zero)
			{
				if(operatingSystemType == OperatingSystemType.Windows)
				{
					methodPointer = GetProcAddress(handle, methodName);
				}
				else if(operatingSystemType == OperatingSystemType.Unix)
				{
					methodPointer = dlsym(handle, methodName);
				}
				else if(operatingSystemType == OperatingSystemType.MacOSX)
				{
					methodPointer = macOS_dlsym(handle, methodName);
				}
			}
			if (methodPointer != IntPtr.Zero)
			{
				// NOTE: Starting in .NET 4.5.1, Marshal.GetDelegateForFunctionPointer(IntPtr, Type) is obsolete.
#if NET40
				return Marshal.GetDelegateForFunctionPointer(
					methodPointer, typeof(T)) as T;
#else
				return Marshal.GetDelegateForFunctionPointer<T>(methodPointer);
#endif
			}
			if (missingInMinimal)
			{
				throw new MissingMemberException(
					"Do you have the full version of ICU installed? " +
					$"The method '{methodName}' is not included in the minimal version of ICU.");
			}
			return default(T);
		}

		#endregion

		public static string GetAnsiString(Func<IntPtr, int, Tuple<ErrorCode, int>> lambda,
			int initialLength = 255)
		{
			return GetString(lambda, false, initialLength);
		}

		public static string GetUnicodeString(Func<IntPtr, int, Tuple<ErrorCode, int>> lambda,
			int initialLength = 255)
		{
			return GetString(lambda, true, initialLength);
		}

		private static string GetString(Func<IntPtr, int, Tuple<ErrorCode, int>> lambda,
			bool isUnicodeString = false, int initialLength = 255)
		{
			var length = initialLength;
			var resPtr = Marshal.AllocCoTaskMem(length * 2);
			try
			{
				var (err, outLength) = lambda(resPtr, length);
				if (err != ErrorCode.BUFFER_OVERFLOW_ERROR && err != ErrorCode.STRING_NOT_TERMINATED_WARNING)
					ExceptionFromErrorCode.ThrowIfError(err);
				if (outLength >= length)
				{
					err = ErrorCode.NoErrors; // ignore possible U_BUFFER_OVERFLOW_ERROR or STRING_NOT_TERMINATED_WARNING
					Marshal.FreeCoTaskMem(resPtr);
					length = outLength + 1; // allow room for the terminating NUL (FWR-505)
					resPtr = Marshal.AllocCoTaskMem(length * 2);
					(err, outLength) = lambda(resPtr, length);
				}

				ExceptionFromErrorCode.ThrowIfError(err);

				if (outLength < 0)
					return null;

				var result = isUnicodeString
					? Marshal.PtrToStringUni(resPtr)
					: Marshal.PtrToStringAnsi(resPtr);
				// Strip any garbage left over at the end of the string.
				if (err == ErrorCode.STRING_NOT_TERMINATED_WARNING && result != null)
					return result.Substring(0, outLength);
				return result;
			}
			finally
			{
				Marshal.FreeCoTaskMem(resPtr);
			}
		}

		/// <summary>
		/// This function does cleanup of the enumerator object
		/// </summary>
		/// <param name="en">Enumeration to be closed</param>
		public static void uenum_close(IntPtr en)
		{
			if (Methods.uenum_close == null)
				Methods.uenum_close = GetMethod<MethodsContainer.uenum_closeDelegate>(IcuCommonLibHandle, "uenum_close");
			Methods.uenum_close(en);
		}

		/// <summary>
		/// This function returns the next element as a string, or <c>null</c> after all
		/// elements haven been enumerated.
		/// </summary>
		/// <returns>next element as string, or <c>null</c> after all elements haven been
		/// enumerated</returns>
		public static IntPtr uenum_unext(
			SafeEnumeratorHandle en,
			out int resultLength,
			out ErrorCode status)
		{
			if (Methods.uenum_unext == null)
				Methods.uenum_unext = GetMethod<MethodsContainer.uenum_unextDelegate>(IcuCommonLibHandle, "uenum_unext");
			return Methods.uenum_unext(en, out resultLength, out status);
		}

		public enum LocaleType
		{
			/// <summary>
			/// This is locale the data actually comes from
			/// </summary>
			ActualLocale = 0,
			/// <summary>
			/// This is the most specific locale supported by ICU
			/// </summary>
			ValidLocale = 1,
		}

		public enum CollationAttributeValue
		{
			Default = -1, //accepted by most attributes
			Primary = 0, // primary collation strength
			Secondary = 1, // secondary collation strength
			Tertiary = 2, // tertiary collation strength
			Default_Strength = Tertiary,
			Quaternary = 3, //Quaternary collation strength
			Identical = 15, //Identical collation strength

			Off = 16, //Turn the feature off - works for FrenchCollation, CaseLevel, HiraganaQuaternaryMode, DecompositionMode
			On = 17, //Turn the feature on - works for FrenchCollation, CaseLevel, HiraganaQuaternaryMode, DecompositionMode

			Shifted = 20, // Valid for AlternateHandling. Alternate handling will be shifted
			NonIgnorable = 21, // Valid for AlternateHandling. Alternate handling will be non-ignorable

			LowerFirst = 24, // Valid for CaseFirst - lower case sorts before upper case
			UpperFirst = 25 // Valid for CaseFirst - upper case sorts before lower case
		}

		public enum CollationAttribute
		{
			FrenchCollation,
			AlternateHandling,
			CaseFirst,
			CaseLevel,
			NormalizationMode,
			DecompositionMode = NormalizationMode,
			Strength,
			HiraganaQuaternaryMode,
			NumericCollation,
			AttributeCount
		}

		public enum CollationResult
		{
			Equal = 0,
			Greater = 1,
			Less = -1
		}

		private class MethodsContainer
		{
			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_initDelegate(out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_cleanupDelegate();

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate IntPtr u_getDataDirectoryDelegate();

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_setDataDirectoryDelegate(
				[MarshalAs(UnmanagedType.LPStr)]string directory);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_charNameDelegate(
				int code,
				Character.UCharNameChoice nameChoice,
				IntPtr buffer,
				int bufferLength,
				out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_charDirectionDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_digitDelegate(
				int characterCode,
				byte radix);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_getIntPropertyValueDelegate(
				int characterCode,
				Character.UProperty choice);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_getUnicodeVersionDelegate(out VersionInfo versionArray);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_getVersionDelegate(out VersionInfo versionArray);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate sbyte u_charTypeDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate double u_getNumericValueDelegate(
				int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			// Required because ICU returns a one-byte boolean. Without this C# assumes 4, and picks up 3 more random bytes,
			// which are usually zero, especially in debug builds...but one day we will be sorry.
			[return: MarshalAs(UnmanagedType.I1)]
			internal delegate bool u_ispunctDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			// Required because ICU returns a one-byte boolean. Without this C# assumes 4, and picks up 3 more random bytes,
			// which are usually zero, especially in debug builds...but one day we will be sorry.
			[return: MarshalAs(UnmanagedType.I1)]
			internal delegate bool u_isMirroredDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			// Required because ICU returns a one-byte boolean. Without this C# assumes 4, and picks up 3 more random bytes,
			// which are usually zero, especially in debug builds...but one day we will be sorry.
			[return: MarshalAs(UnmanagedType.I1)]
			internal delegate bool u_iscntrlDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			// Required because ICU returns a one-byte boolean. Without this C# assumes 4, and picks up 3 more random bytes,
			// which are usually zero, especially in debug builds...but one day we will be sorry.
			[return: MarshalAs(UnmanagedType.I1)]
			internal delegate bool u_isspaceDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_foldCaseDelegate(int characterCode, UInt32 options);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_tolowerDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_totitleDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_toupperDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void uenum_closeDelegate(IntPtr en);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate IntPtr uenum_unextDelegate(
				SafeEnumeratorHandle en,
				out int resultLength,
				out ErrorCode status);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_strFoldCaseDelegate(IntPtr dest, int destCapacity, string src,
				int srcLength, UInt32 stringOptions, out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_strToLowerDelegate(IntPtr dest, int destCapacity, string src,
				int srcLength, [MarshalAs(UnmanagedType.LPStr)] string locale, out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_strToTitleDelegate(IntPtr dest, int destCapacity, string src,
				int srcLength, IntPtr titleIter, [MarshalAs(UnmanagedType.LPStr)] string locale,
				out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_strToUpperDelegate(IntPtr dest, int destCapacity, string src,
				int srcLength, [MarshalAs(UnmanagedType.LPStr)] string locale, out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_charMirrorDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_getBidiPairedBracketDelegate(int characterCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int u_getFC_NFKC_ClosureDelegate(int codepoint, IntPtr dest, int destCapacity, out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate int uscript_getScriptExtensionsDelegate(int codepoint, IntPtr destArray, int destCapacity, out ErrorCode errorCode);

			[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
			internal delegate void u_charAgeDelegate(int codepoint, IntPtr versionArray);

			internal u_initDelegate u_init;
			internal u_cleanupDelegate u_cleanup;
			internal u_getDataDirectoryDelegate u_getDataDirectory;
			internal u_setDataDirectoryDelegate u_setDataDirectory;
			internal u_charNameDelegate u_charName;
			internal u_charDirectionDelegate u_charDirection;
			internal u_digitDelegate u_digit;
			internal u_getIntPropertyValueDelegate u_getIntPropertyValue;
			internal u_getUnicodeVersionDelegate u_getUnicodeVersion;
			internal u_getVersionDelegate u_getVersion;
			internal u_charTypeDelegate u_charType;
			internal u_getNumericValueDelegate u_getNumericValue;
			internal u_ispunctDelegate u_ispunct;
			internal u_isMirroredDelegate u_isMirrored;
			internal u_iscntrlDelegate u_iscntrl;
			internal u_isspaceDelegate u_isspace;
			internal u_foldCaseDelegate u_foldCase;
			internal u_tolowerDelegate u_tolower;
			internal u_totitleDelegate u_totitle;
			internal u_toupperDelegate u_toupper;
			internal uenum_closeDelegate uenum_close;
			internal uenum_unextDelegate uenum_unext;
			internal u_strFoldCaseDelegate u_strFoldCase;
			internal u_strToLowerDelegate u_strToLower;
			internal u_strToTitleDelegate u_strToTitle;
			internal u_strToUpperDelegate u_strToUpper;
			internal u_charMirrorDelegate u_charMirror;
			internal u_getBidiPairedBracketDelegate u_getBidiPairedBracket;
			internal u_getFC_NFKC_ClosureDelegate u_getFC_NFKC_Closure;
			internal uscript_getScriptExtensionsDelegate uscript_getScriptExtensions;
			internal u_charAgeDelegate u_charAge;
		}

		/// <summary>get the name of an ICU code point</summary>
		public static void u_init(out ErrorCode errorCode)
		{
			IsInitialized = true;
			if (Methods.u_init == null)
				Methods.u_init = GetMethod<MethodsContainer.u_initDelegate>(IcuCommonLibHandle, "u_init");
			Methods.u_init(out errorCode);
		}

		/// <summary>Clean up the ICU files that could be locked</summary>
		public static void u_cleanup()
		{
			if (Methods.u_cleanup == null)
				Methods.u_cleanup = GetMethod<MethodsContainer.u_cleanupDelegate>(IcuCommonLibHandle, "u_cleanup");
			Methods.u_cleanup();
			IsInitialized = false;
		}

		/// <summary>Return the ICU data directory</summary>
		public static IntPtr u_getDataDirectory()
		{
			if (Methods.u_getDataDirectory == null)
				Methods.u_getDataDirectory = GetMethod<MethodsContainer.u_getDataDirectoryDelegate>(IcuCommonLibHandle, "u_getDataDirectory");
			return Methods.u_getDataDirectory();
		}

		/// <summary>Set the ICU data directory</summary>
		public static void u_setDataDirectory(
			[MarshalAs(UnmanagedType.LPStr)]string directory)
		{
			if (Methods.u_setDataDirectory == null)
				Methods.u_setDataDirectory = GetMethod<MethodsContainer.u_setDataDirectoryDelegate>(IcuCommonLibHandle, "u_setDataDirectory");
			Methods.u_setDataDirectory(directory);
		}

		/// <summary>get the name of an ICU code point</summary>
		public static int u_charName(
			int code,
			Character.UCharNameChoice nameChoice,
			IntPtr buffer,
			int bufferLength,
			out ErrorCode errorCode)
		{
			if (Methods.u_charName == null)
				Methods.u_charName = GetMethod<MethodsContainer.u_charNameDelegate>(IcuCommonLibHandle, "u_charName");
			return Methods.u_charName(code, nameChoice, buffer, bufferLength, out errorCode);
		}

		/// <summary>Returns the bidirectional category value for the code point, which is used in the Unicode bidirectional algorithm</summary>
		public static int u_charDirection(int characterCode)
		{
			if (Methods.u_charDirection == null)
				Methods.u_charDirection = GetMethod<MethodsContainer.u_charDirectionDelegate>(IcuCommonLibHandle, "u_charDirection");
			return Methods.u_charDirection(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		/// get the numeric value for the Unicode digit
		/// </summary>
		/// ------------------------------------------------------------------------------------
		public static int u_digit(
			int characterCode,
			byte radix)
		{
			if (Methods.u_digit == null)
				Methods.u_digit = GetMethod<MethodsContainer.u_digitDelegate>(IcuCommonLibHandle, "u_digit");
			return Methods.u_digit(characterCode, radix);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		/// Gets the property value for an enumerated or integer Unicode property for a code point.
		/// </summary>
		/// <param name="codePoint">The codepoint to look up</param>
		/// <param name="which">The property value to look up</param>
		/// <returns>Numeric value that is directly the property value or, for enumerated
		/// properties, corresponds to the numeric value of the enumerated constant of the
		/// respective property value enumeration type (cast to enum type if necessary). Returns
		/// 0 or 1 (for <c>false/true</c>) for binary Unicode properties. Returns a bit-mask for
		/// mask properties. Returns 0 if <paramref name="which"/> is out of bounds or if the
		/// Unicode version does not have data for the property at all, or not for this code point.
		/// </returns>
		/// <remarks>Consider adding a specific implementation for each property!</remarks>
		/// ------------------------------------------------------------------------------------
		public static int u_getIntPropertyValue(
			int codePoint,
			Character.UProperty which)
		{
			if (Methods.u_getIntPropertyValue == null)
				Methods.u_getIntPropertyValue = GetMethod<MethodsContainer.u_getIntPropertyValueDelegate>(IcuCommonLibHandle, "u_getIntPropertyValue");
			return Methods.u_getIntPropertyValue(codePoint, which);
		}

		public static void u_getUnicodeVersion(out VersionInfo versionArray)
		{
			if (Methods.u_getUnicodeVersion == null)
				Methods.u_getUnicodeVersion = GetMethod<MethodsContainer.u_getUnicodeVersionDelegate>(IcuCommonLibHandle, "u_getUnicodeVersion");
			Methods.u_getUnicodeVersion(out versionArray);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		/// Gets the ICU release version.
		/// </summary>
		/// <param name="versionArray">Stores the version information for ICU.</param>
		/// ------------------------------------------------------------------------------------
		public static void u_getVersion(out VersionInfo versionArray)
		{
			if (Methods.u_getVersion == null)
				Methods.u_getVersion = GetMethod<MethodsContainer.u_getVersionDelegate>(IcuCommonLibHandle, "u_getVersion");
			Methods.u_getVersion(out versionArray);
		}

		/// <summary>
		/// Get the general character type.
		/// </summary>
		/// <param name="characterCode"></param>
		/// <returns></returns>
		public static sbyte u_charType(int characterCode)
		{
			if (Methods.u_charType == null)
				Methods.u_charType = GetMethod<MethodsContainer.u_charTypeDelegate>(IcuCommonLibHandle, "u_charType");
			return Methods.u_charType(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		///Get the numeric value for a Unicode code point as defined in the Unicode Character Database.
		///A "double" return type is necessary because some numeric values are fractions, negative, or too large for int32_t.
		///For characters without any numeric values in the Unicode Character Database,
		///this function will return U_NO_NUMERIC_VALUE.
		///
		///Similar to java.lang.Character.getNumericValue(), but u_getNumericValue() also supports negative values,
		///large values, and fractions, while Java's getNumericValue() returns values 10..35 for ASCII letters.
		///</summary>
		///<remarks>
		///  See also:
		///      U_NO_NUMERIC_VALUE
		///  Stable:
		///      ICU 2.2
		/// http://oss.software.ibm.com/icu/apiref/uchar_8h.html#a477
		/// </remarks>
		///<param name="characterCode">Code point to get the numeric value for</param>
		///<returns>Numeric value of c, or U_NO_NUMERIC_VALUE if none is defined.</returns>
		/// ------------------------------------------------------------------------------------
		public static double u_getNumericValue(
			int characterCode)
		{
			if (Methods.u_getNumericValue == null)
				Methods.u_getNumericValue = GetMethod<MethodsContainer.u_getNumericValueDelegate>(IcuCommonLibHandle, "u_getNumericValue");
			return Methods.u_getNumericValue(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		///	Determines whether the specified code point is a punctuation character.
		/// </summary>
		/// <param name="characterCode">the code point to be tested</param>
		/// ------------------------------------------------------------------------------------
		public static bool u_ispunct(
			int characterCode)
		{
			if (Methods.u_ispunct == null)
				Methods.u_ispunct = GetMethod<MethodsContainer.u_ispunctDelegate>(IcuCommonLibHandle, "u_ispunct");
			return Methods.u_ispunct(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		///	Determines whether the code point has the Bidi_Mirrored property.
		///
		///	This property is set for characters that are commonly used in Right-To-Left contexts
		///	and need to be displayed with a "mirrored" glyph.
		///
		///	Same as java.lang.Character.isMirrored(). Same as UCHAR_BIDI_MIRRORED
		/// </summary>
		///	<remarks>
		///	See also:
		///	    UCHAR_BIDI_MIRRORED
		///
		///	Stable:
		///	    ICU 2.0
		///	</remarks>
		/// <param name="characterCode">the code point to be tested</param>
		/// <returns><c>true</c> if the character has the Bidi_Mirrored property</returns>
		/// ------------------------------------------------------------------------------------
		public static bool u_isMirrored(
			int characterCode)
		{
			if (Methods.u_isMirrored == null)
				Methods.u_isMirrored = GetMethod<MethodsContainer.u_isMirroredDelegate>(IcuCommonLibHandle, "u_isMirrored");
			return Methods.u_isMirrored(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		///	Determines whether the specified code point is a control character. A control
		///	character is one of the following:
		/// <list>
		///	<item>ISO 8-bit control character (U+0000..U+001f and U+007f..U+009f)</item>
		///	<item>U_CONTROL_CHAR (Cc)</item>
		///	<item>U_FORMAT_CHAR (Cf)</item>
		///	<item>U_LINE_SEPARATOR (Zl)</item>
		///	<item>U_PARAGRAPH_SEPARATOR (Zp)</item>
		///	</list>
		/// </summary>
		/// <param name="characterCode">the code point to be tested</param>
		/// ------------------------------------------------------------------------------------
		public static bool u_iscntrl(
			int characterCode)
		{
			if (Methods.u_iscntrl == null)
				Methods.u_iscntrl = GetMethod<MethodsContainer.u_iscntrlDelegate>(IcuCommonLibHandle, "u_iscntrl");
			return Methods.u_iscntrl(characterCode);
		}

		/// ------------------------------------------------------------------------------------
		/// <summary>
		///	Determines whether the specified character is a space character.
		/// </summary>
		/// <remarks>
		///	See also:
		///	<list>
		///	<item>u_isJavaSpaceChar</item>
		///	<item>u_isWhitespace</item>
		/// <item>u_isUWhiteSpace</item>
		///	</list>
		///
		///	Stable:
		///	    ICU 2.0
		///	</remarks>
		/// <param name="characterCode">the code point to be tested</param>
		/// ------------------------------------------------------------------------------------
		public static bool u_isspace(
			int characterCode)
		{
			if (Methods.u_isspace == null)
				Methods.u_isspace = GetMethod<MethodsContainer.u_isspaceDelegate>(IcuCommonLibHandle, "u_isspace");
			return Methods.u_isspace(characterCode);
		}

		/// <summary>Map character to its casefold equivalent according to UnicodeData.txt</summary>
		public static int u_foldCase(int characterCode, Character.StringOptions stringOptions)
		{
			if(Methods.u_foldCase == null)
				Methods.u_foldCase = GetMethod<MethodsContainer.u_foldCaseDelegate>(IcuCommonLibHandle, "u_foldCase");
			return Methods.u_foldCase(characterCode, (UInt32)stringOptions);
		}

		/// <summary>Map character to its lowercase equivalent according to UnicodeData.txt</summary>
		public static int u_tolower(int characterCode)
		{
			if (Methods.u_tolower == null)
				Methods.u_tolower = GetMethod<MethodsContainer.u_tolowerDelegate>(IcuCommonLibHandle, "u_tolower");
			return Methods.u_tolower(characterCode);
		}

		/// <summary>Map character to its titlecase equivalent according to UnicodeData.txt</summary>
		public static int u_totitle(int characterCode)
		{
			if (Methods.u_totitle == null)
				Methods.u_totitle = GetMethod<MethodsContainer.u_totitleDelegate>(IcuCommonLibHandle, "u_totitle");
			return Methods.u_totitle(characterCode);
		}

		/// <summary>Map character to its uppercase equivalent according to UnicodeData.txt</summary>
		public static int u_toupper(int characterCode)
		{
			if (Methods.u_toupper == null)
				Methods.u_toupper = GetMethod<MethodsContainer.u_toupperDelegate>(IcuCommonLibHandle, "u_toupper");
			return Methods.u_toupper(characterCode);
		}

		/// <summary>Return the case folded equivalent of the string.</summary>
		public static int u_strFoldCase(IntPtr dest, int destCapacity, string src,
			int srcLength, Character.StringOptions stringOptions, out ErrorCode errorCode)
		{
			if(Methods.u_strFoldCase == null)
				Methods.u_strFoldCase = GetMethod<MethodsContainer.u_strFoldCaseDelegate>(IcuCommonLibHandle, "u_strFoldCase");
			return Methods.u_strFoldCase(dest, destCapacity, src, srcLength, (UInt32)stringOptions, out errorCode);
		}

		/// <summary>Return the lower case equivalent of the string.</summary>
		public static int u_strToLower(IntPtr dest, int destCapacity, string src,
			int srcLength, [MarshalAs(UnmanagedType.LPStr)] string locale, out ErrorCode errorCode)
		{
			if (Methods.u_strToLower == null)
				Methods.u_strToLower = GetMethod<MethodsContainer.u_strToLowerDelegate>(IcuCommonLibHandle, "u_strToLower");
			return Methods.u_strToLower(dest, destCapacity, src, srcLength, locale, out errorCode);
		}

		public static int u_strToTitle(IntPtr dest, int destCapacity, string src,
			int srcLength, [MarshalAs(UnmanagedType.LPStr)] string locale,
			out ErrorCode errorCode)
		{
			return u_strToTitle(dest, destCapacity, src, srcLength, IntPtr.Zero, locale,
				out errorCode);
		}

		/// <summary>Return the title case equivalent of the string.</summary>
		public static int u_strToTitle(IntPtr dest, int destCapacity, string src,
			int srcLength, IntPtr titleIter, [MarshalAs(UnmanagedType.LPStr)] string locale,
			out ErrorCode errorCode)
		{
			if (Methods.u_strToTitle == null)
				Methods.u_strToTitle = GetMethod<MethodsContainer.u_strToTitleDelegate>(IcuCommonLibHandle, "u_strToTitle", true);
			return Methods.u_strToTitle(dest, destCapacity, src, srcLength, titleIter,
				locale, out errorCode);
		}

		/// <summary>Return the upper case equivalent of the string.</summary>
		public static int u_strToUpper(IntPtr dest, int destCapacity, string src,
			int srcLength, [MarshalAs(UnmanagedType.LPStr)] string locale, out ErrorCode errorCode)
		{
			if (Methods.u_strToUpper == null)
				Methods.u_strToUpper = GetMethod<MethodsContainer.u_strToUpperDelegate>(IcuCommonLibHandle, "u_strToUpper");
			return Methods.u_strToUpper(dest, destCapacity, src, srcLength, locale, out errorCode);
		}

		/// <summary>Return the mirrored glyph.</summary>
		public static int u_charMirror(int c)
		{
			if(Methods.u_charMirror == null)
				Methods.u_charMirror = GetMethod<MethodsContainer.u_charMirrorDelegate>(IcuCommonLibHandle, "u_charMirror");
			return Methods.u_charMirror(c);
		}

		/// <summary>Return the mirrored glyph.</summary>
		public static int u_getBidiPairedBracket(int c)
		{
			if(Methods.u_getBidiPairedBracket == null)
				Methods.u_getBidiPairedBracket = GetMethod<MethodsContainer.u_getBidiPairedBracketDelegate>(IcuCommonLibHandle, "u_getBidiPairedBracket");
			return Methods.u_getBidiPairedBracket(c);
		}

		public static int u_getFC_NFKC_Closure(int codepoint, IntPtr dest, int destCapacity, out ErrorCode errorCode)
		{
			if(Methods.u_getFC_NFKC_Closure == null)
				Methods.u_getFC_NFKC_Closure = GetMethod<MethodsContainer.u_getFC_NFKC_ClosureDelegate>(IcuCommonLibHandle, "u_getFC_NFKC_Closure");
			return Methods.u_getFC_NFKC_Closure(codepoint, dest, destCapacity, out errorCode);
		}

		public static int uscript_getScriptExtensions(int codepoint, IntPtr destArray, int destCapacity, out ErrorCode errorCode)
		{
			if(Methods.uscript_getScriptExtensions == null)
				Methods.uscript_getScriptExtensions = GetMethod<MethodsContainer.uscript_getScriptExtensionsDelegate>(IcuCommonLibHandle, "uscript_getScriptExtensions");
			return Methods.uscript_getScriptExtensions(codepoint, destArray, destCapacity, out errorCode);
		}

		public static void u_charAge(int codepoint, IntPtr versionArray)
		{
			if(Methods.u_charAge == null)
				Methods.u_charAge = GetMethod<MethodsContainer.u_charAgeDelegate>(IcuCommonLibHandle, "u_charAge");
			Methods.u_charAge(codepoint, versionArray);
		}

	}
}
