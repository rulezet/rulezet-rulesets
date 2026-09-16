rule webshell_aspx_simpleseesharp
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "ASPX Webshell allowing CRUD of files and cmd execution."
        hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-11-12T16:45:07Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4969
        version = 6

    strings:
        $header = "<%@ Page Language=\"C#\" %>"
        $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

    condition:
        filesize < 1KB and
        $header at 0 and
        $body
}