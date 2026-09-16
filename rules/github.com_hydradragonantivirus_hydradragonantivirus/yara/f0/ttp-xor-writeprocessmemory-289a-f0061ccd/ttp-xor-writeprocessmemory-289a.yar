rule TTP_XOR_WriteProcessMemory_289a {
  strings:
    $key_289a = { 7f e8 [2] 4d ca [2] 4b ff [2] 65 ff [2] 5a e3 }

  condition:
    any of them
}