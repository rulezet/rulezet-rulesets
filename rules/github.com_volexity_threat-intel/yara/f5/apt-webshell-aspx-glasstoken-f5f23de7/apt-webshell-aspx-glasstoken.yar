import "math"
rule apt_webshell_aspx_glasstoken: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-12"
        description = "Detection for a custom webshell seen on Exchange server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
        hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
        os = "win"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-30T18:48:20Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9994
        version = 6

    strings:
        $s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
        $re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

    condition:
        for any i in (0..math.min(#s1,100)):
            (
                $re in (@s1[i]..@s1[i]+512)
            )
}