rule Prikormka
{
    meta:
        Author      = "Anton Cherepanov"
        Date        = "2016/05/10"
        Description = "Operation Groundbait"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "threatintel@eset.com"
        License = "BSD 2-Clause"
        id = "6073aa34-d385-5ae8-b97d-9b3d61015aae"
    condition:
        PrikormkaDropper or PrikormkaModule or PrikormkaEarlyVersion
}