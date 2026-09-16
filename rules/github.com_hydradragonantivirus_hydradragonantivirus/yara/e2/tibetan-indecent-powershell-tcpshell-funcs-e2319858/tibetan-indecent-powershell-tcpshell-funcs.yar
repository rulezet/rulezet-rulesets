rule tibetan_indecent_powershell_tcpshell_funcs {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $class  = "public class ReverseTCPShell" ascii wide nocase
    $func1  = "public static void run" ascii wide nocase
    $func2  = "public static void runth" ascii wide nocase
    $func3  = "public static void start" ascii wide nocase
    $func4  = "public static bool isOnline" ascii wide nocase
    $func5  = "public static void startCmd" ascii wide nocase
    $func6  = "public static void CmdExited" ascii wide nocase
    $func7  = "public static void DataReceived" ascii wide nocase
    $func8  = "public static void FileReceive" ascii wide nocase
    $func9  = "public static void CmdManager" ascii wide nocase
    $func10 = "public static void SortOutputHandler" ascii wide nocase
    $func11 = "public static void SendLoginInfo" ascii wide nocase
    $func12 = "public static void Send" ascii wide nocase
    $func13 = "public static int SendWithSplit" ascii wide nocase

  condition:
    6 of them

}