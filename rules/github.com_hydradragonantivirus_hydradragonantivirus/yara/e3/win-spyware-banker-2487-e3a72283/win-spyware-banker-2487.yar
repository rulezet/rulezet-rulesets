rule Win_Spyware_Banker_2487
{
strings:
	$a0 = { e8073aec3aa70ee66ab052d03bda25fa92348189da26e7a6241f9ff7d9bd3ee32324feee095a8f7a6610ff9666113c84cad52454436316527b1f8c7a2cc7e05924ebaa79d186d56ff261 }


condition:
	$a0
}