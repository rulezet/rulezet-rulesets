rule MW_neuron2_loader_strings : Turla APT loader
{
    meta:
        description = "Rule for detection of Neuron2 based on strings within the loader"
        author = "NCSC"
        family = "Turla"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        date = "2018-01-18"
        hash1 = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
    strings:
        $ = "dcom_api" ascii
        $ = "http://*:80/OWA/OAB/" ascii
        $ = "https://*:443/OWA/OAB/" ascii
        $ = "dcomnetsrv.cpp" wide
        $ = "dcomnet.dll" ascii
        $ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 2 of them
}