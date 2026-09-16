rule TTP_XOR_WriteProcessMemory_83ed {
  strings:
    $key_83ed = { d4 9f [2] e6 bd [2] e0 88 [2] ce 88 [2] f1 94 }

  condition:
    any of them
}