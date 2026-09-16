rule ConventionEngine_Keyword_1337
{
 meta:
 author = "@itsreallynick"
 description = "Searching for PE files with PDB path keywords, terms or anomalies. -YOUR BOY CARR"
 sample_md5 = "e9ecca14f19fe192fc48e714a649cadd"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}[a-zA-Z]?:?\\[\\\s|*\s]?.{0,250}\\[l1]33[7t][\\\s|*\s]?.{0,250}\.pdb\x00/ nocase
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}