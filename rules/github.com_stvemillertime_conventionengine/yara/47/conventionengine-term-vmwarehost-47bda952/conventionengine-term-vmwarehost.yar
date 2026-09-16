rule ConventionEngine_Term_VmwareHost
{
 meta:
 author = "@itsreallynick"
 description = "Searching for PE files with PDB path keywords, terms, or anomalies. -YOUR BOY CARR"
 sample_md5 = "2742750991eb6687440ef53a7a93df94"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\\\\vmware-host\\[\x00-\xFF]{0,200}\.pdb\x00/ nocase ascii
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}