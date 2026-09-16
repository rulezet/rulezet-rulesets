rule TTP_XOR_WriteProcessMemory_b8ed {
  strings:
    $key_b8ed = { ef 9f [2] dd bd [2] db 88 [2] f5 88 [2] ca 94 }

  condition:
    any of them
}