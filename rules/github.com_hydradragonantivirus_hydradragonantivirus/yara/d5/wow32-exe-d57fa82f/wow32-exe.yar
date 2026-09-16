rule wow32_exe
{
       meta:
              description = "wow32-exe"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "avsupport@autoitscript.com" wide ascii
              $b = "compiled AutoIt script" wide ascii

       condition:
              $a and $b
}