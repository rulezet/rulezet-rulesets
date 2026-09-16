rule TTP_XOR_WriteProcessMemory_de88 {
  strings:
    $key_de88 = { 89 fa [2] bb d8 [2] bd ed [2] 93 ed [2] ac f1 }

  condition:
    any of them
}