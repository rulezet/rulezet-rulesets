rule PEiD_02215_tElock_v0_98b2_
{
    meta:
        description = "[tElock v0.98b2]"
        ep_only = "true"
    strings:
        $a = {E9 1B E4 FF FF}
    condition:
        $a
}