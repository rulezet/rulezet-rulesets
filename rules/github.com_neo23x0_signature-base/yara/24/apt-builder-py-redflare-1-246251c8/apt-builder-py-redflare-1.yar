rule APT_Builder_PY_REDFLARE_1
{
    meta:
        description = "Detects FireEye's Python Redflar"
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "3b5ad25d-ce66-572e-9a91-40a73b8fd447"
    strings:
        $1 = "LOAD_OFFSET_32 = 0x612"
        $2 = "LOAD_OFFSET_64 = 0x611"
        $3 = "class RC4:"
        $4 = "struct.pack('<Q' if is64b else '<L'"
        $5 = "stagerConfig['comms']['config']"
        $6 = "_x86.dll"
        $7 = "_x64.dll"
    condition:
        all of them and @1[1] < @2[1] and @2[1] < @3[1] and @3[1] < @4[1] and @4[1] < @5[1]
}