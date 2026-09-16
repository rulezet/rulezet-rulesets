rule ConventionEngine_Keyword_Admin
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "67fff57bb44d3458b17f0c7a7a45f405"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}Admin[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 $this = /RSDS[\x00-\xFF]{20}[a-zA-Z]:\\[\x00-\xFF]{0,200}administrator[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre and not $this
}