rule ConventionEngine_Keyword_UAC
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "2e62974fbce2fc1bbde763b986ad7b77"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}uac[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}