rule CredTheft_MSIL_ADPassHunt_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public ADPassHunt project."
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "35fb8032-c73a-549f-9bd9-409f7050bdb0"
    strings:
        $typelibguid = "15745B9E-A059-4AF1-A0D8-863E349CD85D" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}