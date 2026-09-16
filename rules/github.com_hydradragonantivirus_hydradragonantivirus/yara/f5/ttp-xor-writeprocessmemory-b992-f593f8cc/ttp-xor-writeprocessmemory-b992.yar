rule TTP_XOR_WriteProcessMemory_b992 {
  strings:
    $key_b992 = { ee e0 [2] dc c2 [2] da f7 [2] f4 f7 [2] cb eb }

  condition:
    any of them
}