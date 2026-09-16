rule ConventionEngine_Keyword_0day
{
 meta:
 author = "@a_tweeter_user"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e8df15f480b7044cf44faff4273dba8f"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}0day[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}