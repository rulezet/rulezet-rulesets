rule TTP_XOR_WriteProcessMemory_cd38 {
  strings:
    $key_cd38 = { 9a 4a [2] a8 68 [2] ae 5d [2] 80 5d [2] bf 41 }

  condition:
    any of them
}