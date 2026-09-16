rule rule_Invoke_Obfuscation_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Obfuscation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Obfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_Obfuscation_offensive_tool_keyword = "\"Don't use this for evil, please\"" nocase ascii wide
                        $string2_Invoke_Obfuscation_offensive_tool_keyword = /\/Invoke\-Obfuscation\.git/ nocase ascii wide
                        $string3_Invoke_Obfuscation_offensive_tool_keyword = /\\Obfuscated_Command\.txt/ nocase ascii wide
                        $string4_Invoke_Obfuscation_offensive_tool_keyword = "3615ddbae2c65e978aa8006c26b5c4a66c2e9433a1460b17ef700a39a708e5c1" nocase ascii wide
                        $string5_Invoke_Obfuscation_offensive_tool_keyword = "40ce2ea4f4a90332a6e554ddbd9b801e22df018458127ae6ad1243c7d25a5523" nocase ascii wide
                        $string6_Invoke_Obfuscation_offensive_tool_keyword = "46793c55c24e616a0d4eaaa0090b70bdde05e50c1b58da753d09063e6e838cc6" nocase ascii wide
                        $string7_Invoke_Obfuscation_offensive_tool_keyword = "525bb5e67378b9bdc298aceb9e0108603741ae334e8ce748222999fcb2f1d818" nocase ascii wide
                        $string8_Invoke_Obfuscation_offensive_tool_keyword = "5ed84b98241dd1db44e9e3beae6ec07ce8c64cd9200b73954617113578f91317" nocase ascii wide
                        $string9_Invoke_Obfuscation_offensive_tool_keyword = "5fa4acad2bf202e61149a7f47189c4d60ac2823ea26d0f449912ab9d28ad0806" nocase ascii wide
                        $string10_Invoke_Obfuscation_offensive_tool_keyword = "77c88d4c67b3600e78f82c938d2ef72525277647a27692b2114c9688bf1da121" nocase ascii wide
                        $string11_Invoke_Obfuscation_offensive_tool_keyword = "9521883a37c093f31e9d3fde7d3293f637ea51ce573c3fa7967843b7e51d8dd0" nocase ascii wide
                        $string12_Invoke_Obfuscation_offensive_tool_keyword = "9c409702151446f1eb8d951b45a902f2dbad1ebeacab9dd9beeaa5530e65ad0c" nocase ascii wide
                        $string13_Invoke_Obfuscation_offensive_tool_keyword = "a10190903dfb52127ae37214a8c0124c68fc2f7fc91d0bae55eb9f556fa3c8dd" nocase ascii wide
                        $string14_Invoke_Obfuscation_offensive_tool_keyword = "a83c33f484a2cbff3bbefdf51880714968930f69778e8921d8182d2b96e03314" nocase ascii wide
                        $string15_Invoke_Obfuscation_offensive_tool_keyword = "abd9f4b93fc3f2bb0612bfbdef4e0da8797e985e7377ee0c08c2b5b5198c2743" nocase ascii wide
                        $string16_Invoke_Obfuscation_offensive_tool_keyword = "c39d2a1c303847785a2a2af357dd948f5e6ec8194eb427c52a391db90de34f72" nocase ascii wide
                        $string17_Invoke_Obfuscation_offensive_tool_keyword = "cecbe047e33d2dc3bc06cc7a62546a4e1a793d8da1dde4ba3aa021f944930d6d" nocase ascii wide
                        $string18_Invoke_Obfuscation_offensive_tool_keyword = "d0a9150d-b6a4-4b17-a325-e3a24fed0aa9" nocase ascii wide
                        $string19_Invoke_Obfuscation_offensive_tool_keyword = "d683205c9fad76e28a8e4cd0d72285e9a8573cc95c8b77f30186089459675817" nocase ascii wide
                        $string20_Invoke_Obfuscation_offensive_tool_keyword = "danielbohannon/Invoke-Obfuscation" nocase ascii wide
                        $string21_Invoke_Obfuscation_offensive_tool_keyword = "e403c105e8167585b1c431cdc86c943a8f93e876b3940668d088b976d8a1e9a2" nocase ascii wide
                        $string22_Invoke_Obfuscation_offensive_tool_keyword = "Invoke-Obfuscation" nocase ascii wide
                        $string23_Invoke_Obfuscation_offensive_tool_keyword = /Out\-CompressedCommand\.ps1/ nocase ascii wide
                        $string24_Invoke_Obfuscation_offensive_tool_keyword = /Out\-EncodedAsciiCommand\.ps1/ nocase ascii wide
                        $string25_Invoke_Obfuscation_offensive_tool_keyword = /Out\-EncodedBinaryCommand\.ps1/ nocase ascii wide
                        $string26_Invoke_Obfuscation_offensive_tool_keyword = /Out\-EncodedBXORCommand\.ps1/ nocase ascii wide
                        $string27_Invoke_Obfuscation_offensive_tool_keyword = /Out\-EncodedOctalCommand\.ps1/ nocase ascii wide
                        $string28_Invoke_Obfuscation_offensive_tool_keyword = /Out\-EncodedSpecialCharOnlyCommand\.ps1/ nocase ascii wide
                        $string29_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedArrayExpressionAst " nocase ascii wide
                        $string30_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedArrayLiteralAst " nocase ascii wide
                        $string31_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedAssignmentStatementAst " nocase ascii wide
                        $string32_Invoke_Obfuscation_offensive_tool_keyword = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
                        $string33_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedAstsReordered " nocase ascii wide
                        $string34_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedAttributeAst " nocase ascii wide
                        $string35_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedAttributeBaseAst " nocase ascii wide
                        $string36_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedAttributedExpressionAst " nocase ascii wide
                        $string37_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedBaseCtorInvokeMemberExpressionAst " nocase ascii wide
                        $string38_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedBinaryExpressionAst " nocase ascii wide
                        $string39_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedBlockStatementAst " nocase ascii wide
                        $string40_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedBreakStatementAst " nocase ascii wide
                        $string41_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCatchClauseAst " nocase ascii wide
                        $string42_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedChildrenAst " nocase ascii wide
                        $string43_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCommandAst " nocase ascii wide
                        $string44_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCommandBaseAst " nocase ascii wide
                        $string45_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCommandElementAst " nocase ascii wide
                        $string46_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCommandExpressionAst " nocase ascii wide
                        $string47_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedCommandParameterAst " nocase ascii wide
                        $string48_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedConfigurationDefinitionAst " nocase ascii wide
                        $string49_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedConstantExpressionAst " nocase ascii wide
                        $string50_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedContinueStatementAst " nocase ascii wide
                        $string51_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedConvertExpressionAst " nocase ascii wide
                        $string52_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedDataStatementAst " nocase ascii wide
                        $string53_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedDoUntilStatementAst " nocase ascii wide
                        $string54_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedDoWhileStatementAst " nocase ascii wide
                        $string55_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedDynamicKeywordStatementAst " nocase ascii wide
                        $string56_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedErrorExpressionAst " nocase ascii wide
                        $string57_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedErrorStatementAst " nocase ascii wide
                        $string58_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedExitStatementAst " nocase ascii wide
                        $string59_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedExpandableStringExpressionAst " nocase ascii wide
                        $string60_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedExpressionAst " nocase ascii wide
                        $string61_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedFileRedirectionAst " nocase ascii wide
                        $string62_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedForEachStatementAst " nocase ascii wide
                        $string63_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedForStatementAst " nocase ascii wide
                        $string64_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedFunctionDefinitionAst " nocase ascii wide
                        $string65_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedFunctionMemberAst " nocase ascii wide
                        $string66_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedHashtableAst " nocase ascii wide
                        $string67_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedIfStatementAst " nocase ascii wide
                        $string68_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedIndexExpressionAst " nocase ascii wide
                        $string69_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedInvokeMemberExpressionAst " nocase ascii wide
                        $string70_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedLabeledStatementAst " nocase ascii wide
                        $string71_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedLoopStatementAst " nocase ascii wide
                        $string72_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedMemberAst " nocase ascii wide
                        $string73_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedMemberExpressionAst " nocase ascii wide
                        $string74_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedMergingRedirectionAst " nocase ascii wide
                        $string75_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedNamedAttributeArgumentAst " nocase ascii wide
                        $string76_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedNamedBlockAst " nocase ascii wide
                        $string77_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedParamBlockAst " nocase ascii wide
                        $string78_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedParameterAst " nocase ascii wide
                        $string79_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedParenExpressionAst " nocase ascii wide
                        $string80_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedPipelineAst " nocase ascii wide
                        $string81_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedPipelineBaseAst " nocase ascii wide
                        $string82_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedPropertyMemberAst " nocase ascii wide
                        $string83_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedRedirectionAst " nocase ascii wide
                        $string84_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedReturnStatementAst " nocase ascii wide
                        $string85_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedScriptBlockAst " nocase ascii wide
                        $string86_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedScriptBlockExpressionAst " nocase ascii wide
                        $string87_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedStatementAst " nocase ascii wide
                        $string88_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedStatementBlockAst " nocase ascii wide
                        $string89_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedStringCommand" nocase ascii wide
                        $string90_Invoke_Obfuscation_offensive_tool_keyword = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
                        $string91_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedStringConstantExpressionAst " nocase ascii wide
                        $string92_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedSubExpressionAst " nocase ascii wide
                        $string93_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedSwitchStatementAst " nocase ascii wide
                        $string94_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedThrowStatementAst " nocase ascii wide
                        $string95_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTokenCommand" nocase ascii wide
                        $string96_Invoke_Obfuscation_offensive_tool_keyword = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
                        $string97_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTrapStatementAst " nocase ascii wide
                        $string98_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTryStatementAst " nocase ascii wide
                        $string99_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTypeConstraintAst " nocase ascii wide
                        $string100_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTypeDefinitionAst " nocase ascii wide
                        $string101_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedTypeExpressionAst " nocase ascii wide
                        $string102_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedUnaryExpressionAst " nocase ascii wide
                        $string103_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedUsingExpressionAst " nocase ascii wide
                        $string104_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedUsingStatementAst " nocase ascii wide
                        $string105_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedVariableExpressionAst " nocase ascii wide
                        $string106_Invoke_Obfuscation_offensive_tool_keyword = "Out-ObfuscatedWhileStatementAst " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}