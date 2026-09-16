rule PK_LibertyFreightDelivery_express : LibertyFreightDelivery
{
    meta:
        description = "Phishing Kit impersonating Liberty Freight Delivery company"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-02-15"
        comment = "Phishing Kit - LibertyFreightDelivery - '<title>Express Mail</title>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "home"
        $spec_dir2 = "Doc"
        $spec_dir3 = "functions"
                $spec_file = "lopo.html"
        $spec_file2 = "trackingScript.php"
        $spec_file3 = "blog_details.html"
        $spec_file4 = "contact_process.php"
        $spec_file5 = "SHIPMENT.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}