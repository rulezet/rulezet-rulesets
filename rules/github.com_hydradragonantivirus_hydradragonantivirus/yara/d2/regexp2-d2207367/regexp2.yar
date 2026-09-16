rule RegExp2
{
    strings:
        $re1 = /[0-9a-zA-Z]{32}/
    condition:
        $re1
}