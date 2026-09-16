rule HKTL_Release_dllTest_RID2E9F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:22:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ";;;Y;`;d;h;l;p;t;x;|;" 
      $s1 = "0 0&00060K0R0X0f0l0q0w0" 
      $s2 = ": :$:(:,:0:4:8:D:`=d=" 
      $s3 = "4@5P5T5\\5T7\\7d7l7t7|7" 
      $s4 = "1,121>1C1K1Q1X1^1e1k1s1y1" 
      $s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9" 
      $s6 = "0)0O0\\0a0o0\"1E1P1q1" 
      $s7 = "<.<I<d<h<l<p<t<x<|<" 
      $s8 = "3&31383>3F3Q3X3`3f3w3|3" 
      $s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z=" 
   condition: 
      all of them
}