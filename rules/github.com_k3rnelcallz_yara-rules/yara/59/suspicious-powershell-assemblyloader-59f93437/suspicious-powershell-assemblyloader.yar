rule Suspicious_PowerShell_AssemblyLoader
{
    meta:
        description = "Detects PowerShell scripts loading assemblies from memory and hiding payloads"
        author = "k3rnelcallz"
        sha256 = "56e0cfc0fb789f7d8d7cef0b8497eef95563f46bb383d5f38061347657eaa445"
		source = "malwarebazaar"
        creation_date = "1-12-25"
		last_modified = "2-12-25"
		source = "Malwarebazaar"
		category = "Info"

    strings:
                $load = "[System.Reflection.Assembly]::Load"
        $invoke = ".Invoke("

                $getProcess = "Get-Process"
        $mz_b64 = "TVqQAAMAAAAEAAAA"

                $aspnet_compiler = "Aspnet_compiler.exe"

                $blackhawk = "BLACKHAWK.DOWN"
        $shoot     = "SHOOT"

    condition:
                $load and $invoke
                and ($getProcess or $mz_b64)
                and any of ($blackhawk,$shoot,$aspnet_compiler)
}