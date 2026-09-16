import "pe"
rule Batel_export_function
{

    meta:
        author = "@j0sm1"
        date = "2016/10/15"
        description = "Batel backdoor"
        reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99"
        filetype = "binary"

    condition:
        pe.exports("run_shell") and pe.imports("kernel32.dll","GetTickCount") and pe.imports("kernel32.dll","IsDebuggerPresent") and pe.imports("msvcr100.dll","_crt_debugger_hook") and pe.imports("kernel32.dll","TerminateProcess") and pe.imports("kernel32.dll","UnhandledExceptionFilter")
}