rule PEiD_02408_UPX____www_upx_sourceforge_net_
{
    meta:
        description = "[UPX -> www.upx.sourceforge.net]"
        ep_only = "false"
    strings:
        $a = {60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF}
    condition:
        $a
}