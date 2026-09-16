rule sig_20151210_03a0151c0b69b3d52d1acfe7b4b70e04 {
  meta:
    description = "datamaliciousorder - file 20151210_03a0151c0b69b3d52d1acfe7b4b70e04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fafea41d9340f8c183e572ad2e02250017cbf8ae83508d175848435e2a2f998"

  strings:
    $s1  = "function ZbBhxID(mcjVeEeaNzsvJsYnrpWjYBkdZxlDZZjpMZAj) {return !isNaN(parseFloat(mcjVeEeaNzsvJsYnrpWjYBkdZxlDZZjpMZAj)) && isFin" ascii
    $s2  = "function ZbBhxID(mcjVeEeaNzsvJsYnrpWjYBkdZxlDZZjpMZAj) {return !isNaN(parseFloat(mcjVeEeaNzsvJsYnrpWjYBkdZxlDZZjpMZAj)) && isFin" ascii
    $s3  = "function HlxBsCftamKgyyhcfCtZjnHTNJZKFFmoYhIWyqRaIxfJDLVjQVEwyN(GNypFtFSCGUZs,NFNtFROkgiSWWA){ return TVQve[NOjKn(GNypFtFSCGUZs[" ascii
    $s4  = "function NOjKn(YDdxLcuGLYH,EXoCfZrDLhPCT,CzEIwHPz){KRMN=parseInt(YDdxLcuGLYH,EXoCfZrDLhPCT);KNVFI=KRMN.toString(CzEIwHPz);return" ascii
    $s5  = "function NOjKn(YDdxLcuGLYH,EXoCfZrDLhPCT,CzEIwHPz){KRMN=parseInt(YDdxLcuGLYH,EXoCfZrDLhPCT);KNVFI=KRMN.toString(CzEIwHPz);return" ascii
    $s6  = "function EtGCKRkXppvxMBJmY(Fzfuu){BXiyqKXzWAJ= '';for(nCirmjzNxVL=(-9+9)/460; nCirmjzNxVL < (668+896)/782; nCirmjzNxVL++) {tFdNi" ascii
    $s7  = " KNVFI;}function bETWGeObJcBsGJF(hpTLKWVxbrigjHweA){eval(hpTLKWVxbrigjHweA)}" fullword ascii
    $s8  = " return BXiyqKXzWAJ}" fullword ascii
    $s9  = "function HlxBsCftamKgyyhcfCtZjnHTNJZKFFmoYhIWyqRaIxfJDLVjQVEwyN(GNypFtFSCGUZs,NFNtFROkgiSWWA){ return TVQve[NOjKn(GNypFtFSCGUZs[" ascii
    $s10 = "function hSDzPcWXwNE(AptqQMbj,FyhHJo){return AptqQMbj.split(FyhHJo)}" fullword ascii
    $s11 = "yidT[nCirmjzNxVL]=(-345+345)/398; while(true) { if(tFdNiyidT[nCirmjzNxVL] > Fzfuu[nCirmjzNxVL].length-(537+118)/655) { break; } " ascii
    $s12 = "function EtGCKRkXppvxMBJmY(Fzfuu){BXiyqKXzWAJ= '';for(nCirmjzNxVL=(-9+9)/460; nCirmjzNxVL < (668+896)/782; nCirmjzNxVL++) {tFdNi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}