rule mmf: MMF
{
    meta:
        author = "Rafa Bono"
        file_info = "Yamaha SMAF Synthetic music Mobile Application Format"

    strings:
        $a = {4D 4D 4D 44}

    condition:
       $a at 0
}