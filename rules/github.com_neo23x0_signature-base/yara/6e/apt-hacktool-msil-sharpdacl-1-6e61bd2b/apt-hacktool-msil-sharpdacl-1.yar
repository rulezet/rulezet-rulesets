rule APT_HackTool_MSIL_SHARPDACL_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "13f4e3ea-1e36-5fad-9197-66511d6f026a"
    strings:
        $typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}