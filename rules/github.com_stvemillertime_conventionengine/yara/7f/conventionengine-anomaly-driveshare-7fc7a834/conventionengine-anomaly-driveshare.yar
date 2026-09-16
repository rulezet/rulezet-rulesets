rule ConventionEngine_Anomaly_DriveShare
{
 meta:
 author = "@stvemillertime"
 description = "Searching for PE files with PDB path keywords, terms or anomalies."
 sample_md5 = "e7414d82d69b902b5bc1efd0f3e201d7"
 ref_blog = "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
 strings:
 $pcre = /RSDS[\x00-\xFF]{20}\\.{0,50}\\[a-zA-Z]\$\\[\x00-\xFF]{0,200}\.pdb\x00/ nocase
 condition:
 (uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and $pcre
}