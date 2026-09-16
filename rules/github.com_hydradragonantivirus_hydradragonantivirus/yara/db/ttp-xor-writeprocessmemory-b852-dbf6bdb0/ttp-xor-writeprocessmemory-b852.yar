rule TTP_XOR_WriteProcessMemory_b852 {
  strings:
    $key_b852 = { ef 20 [2] dd 02 [2] db 37 [2] f5 37 [2] ca 2b }

  condition:
    any of them
}