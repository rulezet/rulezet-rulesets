rule xaml: XAML
{
    meta:
        author = "Joan Bono"
        file_info = "Microsoft Extensible Application Markup Language"

    strings:
        $a = {EF BB BF 3C}

    condition:
       $a
}