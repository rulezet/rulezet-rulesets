rule chr_obfuscation
{
    meta:
        description = "PHP with string building using hard coded values in chr()"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "d771409e152d0fabae45ea192076d45e"
        hash = "543624bec87272974384c8ab77f2357a"
        hash = "cf2ab009cbd2576a806bfefb74906fdf"

    strings:
        $obf = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}