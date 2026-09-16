rule TTP_XOR_WriteProcessMemory_a109 {
  strings:
    $key_a109 = { f6 7b [2] c4 59 [2] c2 6c [2] ec 6c [2] d3 70 }

  condition:
    any of them
}