rule gh0st

{

meta:
	author = "https://github.com/jackcr/"

   strings:
      $a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
      $b = "Gh0st Update"

   condition:
      any of them

}