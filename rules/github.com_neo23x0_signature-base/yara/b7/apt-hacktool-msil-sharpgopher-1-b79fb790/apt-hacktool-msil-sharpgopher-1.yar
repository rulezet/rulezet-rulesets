rule APT_HackTool_MSIL_SHARPGOPHER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "cc8eb9cd-9a51-5fab-b0a4-247baaa69dd7"
    strings:
        $typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}