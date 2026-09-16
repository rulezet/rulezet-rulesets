rule RegExp1
{
    strings:
        $re1 = /(([0-9a-fA-F]{8}[-]?){5})/
    condition:
        $re1
}