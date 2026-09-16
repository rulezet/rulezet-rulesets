rule TTP_XOR_WriteProcessMemory_89d3 {
  strings:
    $key_89d3 = { de a1 [2] ec 83 [2] ea b6 [2] c4 b6 [2] fb aa }

  condition:
    any of them
}