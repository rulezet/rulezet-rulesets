rule TTP_XOR_WriteProcessMemory_b8fa {
  strings:
    $key_b8fa = { ef 88 [2] dd aa [2] db 9f [2] f5 9f [2] ca 83 }

  condition:
    any of them
}