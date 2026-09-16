import "pe"
rule Suspicious_Python_PyArmor_Dropper {
    meta:
        description = "Detects packed Python malware utilizing PyInstaller and PyArmor with specific embedded payload paths"
        author = "k3rnelcallz"
        sha256 = "9d213d633161dd70b082f47ff0a55cacdd37e871af84e9da17f8ab51555d764d"
        family = "trojan"
        threatlevel = "low"
    strings:
        $pyarmor_runtime = "pyarmor_runtime_000000" ascii
        $payload_exe = "bdata_p002\\uusd.exe" ascii
        $payload_js1 = "bdata_p002\\002_b.js" ascii
        $payload_js2 = "bdata_p002\\002_n.js" ascii
        $pyinstaller_marker = "PyInstaller" ascii
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and 
        $pyinstaller_marker and 
        $pyarmor_runtime and 
        any of ($payload_exe, $payload_js1, $payload_js2)
}