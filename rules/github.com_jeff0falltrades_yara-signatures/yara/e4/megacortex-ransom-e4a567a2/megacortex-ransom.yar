rule megacortex_ransom {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $megacortex = "corrupted with MegaCortex" nocase
        $tsv = ".tsv"
        $morpheus = "We can only show you the door"
        $files = "email to us 2 files from random computers"
        $email_1 = "shawhart1542925@mail.com"
        $email_2 = "anderssperry6654818@mail.com"
        $email_3 = "ezequielgramlich6204294@mail.com"
        $email_4 = "cammostyn9012404@mail.com"

    condition:
        2 of them
}