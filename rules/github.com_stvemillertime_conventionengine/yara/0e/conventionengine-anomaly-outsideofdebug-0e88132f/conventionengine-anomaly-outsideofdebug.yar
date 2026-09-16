import "pe"
rule ConventionEngine_Anomaly_OutsideOfDebug
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "bf0fea133818387cca7eaef5a52c0aed"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,500}\.pdb\x00/
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address == 0
}