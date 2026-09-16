rule Dubnium_Sample_5_RID2D3A : DEMO EXE FILE G0012 MAL {
   meta:
      description = "Detects sample mentioned in the Dubnium Report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2016/06/09/reverse-engineering-dubnium-2?source=mmpc"
      date = "2016-06-10 10:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
      hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
      hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
      tags = "DEMO, EXE, FILE, G0012, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$innn[i$[i$^i[e[mdi[m$jf1Wehn[^Whl[^iin_hf$11mahZijnjbi[^[W[f1n$dej$[hn]1[W1ni1l[ic1j[mZjchl$$^he[[j[a[1_iWc[e[" fullword ascii
      $s2 = "h$YWdh[$ij7^e$n[[_[h[i[[[\\][1$1[[j1W1[1cjm1[$[k1ZW_$$ncn[[Inbnnc[I9enanid[fZCX" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 9000KB and all of them
}