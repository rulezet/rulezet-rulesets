rule Invoke_Obfuscation
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Obfuscation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Obfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"Don't use this for evil, please\"" nocase ascii wide
                        $string2 = /\/Invoke\-Obfuscation\.git/ nocase ascii wide
                        $string3 = /\\Obfuscated_Command\.txt/ nocase ascii wide
                        $string4 = "3615ddbae2c65e978aa8006c26b5c4a66c2e9433a1460b17ef700a39a708e5c1" nocase ascii wide
                        $string5 = "40ce2ea4f4a90332a6e554ddbd9b801e22df018458127ae6ad1243c7d25a5523" nocase ascii wide
                        $string6 = "46793c55c24e616a0d4eaaa0090b70bdde05e50c1b58da753d09063e6e838cc6" nocase ascii wide
                        $string7 = "525bb5e67378b9bdc298aceb9e0108603741ae334e8ce748222999fcb2f1d818" nocase ascii wide
                        $string8 = "5ed84b98241dd1db44e9e3beae6ec07ce8c64cd9200b73954617113578f91317" nocase ascii wide
                        $string9 = "5fa4acad2bf202e61149a7f47189c4d60ac2823ea26d0f449912ab9d28ad0806" nocase ascii wide
                        $string10 = "77c88d4c67b3600e78f82c938d2ef72525277647a27692b2114c9688bf1da121" nocase ascii wide
                        $string11 = "9521883a37c093f31e9d3fde7d3293f637ea51ce573c3fa7967843b7e51d8dd0" nocase ascii wide
                        $string12 = "9c409702151446f1eb8d951b45a902f2dbad1ebeacab9dd9beeaa5530e65ad0c" nocase ascii wide
                        $string13 = "a10190903dfb52127ae37214a8c0124c68fc2f7fc91d0bae55eb9f556fa3c8dd" nocase ascii wide
                        $string14 = "a83c33f484a2cbff3bbefdf51880714968930f69778e8921d8182d2b96e03314" nocase ascii wide
                        $string15 = "abd9f4b93fc3f2bb0612bfbdef4e0da8797e985e7377ee0c08c2b5b5198c2743" nocase ascii wide
                        $string16 = "c39d2a1c303847785a2a2af357dd948f5e6ec8194eb427c52a391db90de34f72" nocase ascii wide
                        $string17 = "cecbe047e33d2dc3bc06cc7a62546a4e1a793d8da1dde4ba3aa021f944930d6d" nocase ascii wide
                        $string18 = "d0a9150d-b6a4-4b17-a325-e3a24fed0aa9" nocase ascii wide
                        $string19 = "d683205c9fad76e28a8e4cd0d72285e9a8573cc95c8b77f30186089459675817" nocase ascii wide
                        $string20 = "danielbohannon/Invoke-Obfuscation" nocase ascii wide
                        $string21 = "e403c105e8167585b1c431cdc86c943a8f93e876b3940668d088b976d8a1e9a2" nocase ascii wide
                        $string22 = "Invoke-Obfuscation" nocase ascii wide
                        $string23 = /Out\-CompressedCommand\.ps1/ nocase ascii wide
                        $string24 = /Out\-EncodedAsciiCommand\.ps1/ nocase ascii wide
                        $string25 = /Out\-EncodedBinaryCommand\.ps1/ nocase ascii wide
                        $string26 = /Out\-EncodedBXORCommand\.ps1/ nocase ascii wide
                        $string27 = /Out\-EncodedOctalCommand\.ps1/ nocase ascii wide
                        $string28 = /Out\-EncodedSpecialCharOnlyCommand\.ps1/ nocase ascii wide
                        $string29 = "Out-ObfuscatedArrayExpressionAst " nocase ascii wide
                        $string30 = "Out-ObfuscatedArrayLiteralAst " nocase ascii wide
                        $string31 = "Out-ObfuscatedAssignmentStatementAst " nocase ascii wide
                        $string32 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
                        $string33 = "Out-ObfuscatedAstsReordered " nocase ascii wide
                        $string34 = "Out-ObfuscatedAttributeAst " nocase ascii wide
                        $string35 = "Out-ObfuscatedAttributeBaseAst " nocase ascii wide
                        $string36 = "Out-ObfuscatedAttributedExpressionAst " nocase ascii wide
                        $string37 = "Out-ObfuscatedBaseCtorInvokeMemberExpressionAst " nocase ascii wide
                        $string38 = "Out-ObfuscatedBinaryExpressionAst " nocase ascii wide
                        $string39 = "Out-ObfuscatedBlockStatementAst " nocase ascii wide
                        $string40 = "Out-ObfuscatedBreakStatementAst " nocase ascii wide
                        $string41 = "Out-ObfuscatedCatchClauseAst " nocase ascii wide
                        $string42 = "Out-ObfuscatedChildrenAst " nocase ascii wide
                        $string43 = "Out-ObfuscatedCommandAst " nocase ascii wide
                        $string44 = "Out-ObfuscatedCommandBaseAst " nocase ascii wide
                        $string45 = "Out-ObfuscatedCommandElementAst " nocase ascii wide
                        $string46 = "Out-ObfuscatedCommandExpressionAst " nocase ascii wide
                        $string47 = "Out-ObfuscatedCommandParameterAst " nocase ascii wide
                        $string48 = "Out-ObfuscatedConfigurationDefinitionAst " nocase ascii wide
                        $string49 = "Out-ObfuscatedConstantExpressionAst " nocase ascii wide
                        $string50 = "Out-ObfuscatedContinueStatementAst " nocase ascii wide
                        $string51 = "Out-ObfuscatedConvertExpressionAst " nocase ascii wide
                        $string52 = "Out-ObfuscatedDataStatementAst " nocase ascii wide
                        $string53 = "Out-ObfuscatedDoUntilStatementAst " nocase ascii wide
                        $string54 = "Out-ObfuscatedDoWhileStatementAst " nocase ascii wide
                        $string55 = "Out-ObfuscatedDynamicKeywordStatementAst " nocase ascii wide
                        $string56 = "Out-ObfuscatedErrorExpressionAst " nocase ascii wide
                        $string57 = "Out-ObfuscatedErrorStatementAst " nocase ascii wide
                        $string58 = "Out-ObfuscatedExitStatementAst " nocase ascii wide
                        $string59 = "Out-ObfuscatedExpandableStringExpressionAst " nocase ascii wide
                        $string60 = "Out-ObfuscatedExpressionAst " nocase ascii wide
                        $string61 = "Out-ObfuscatedFileRedirectionAst " nocase ascii wide
                        $string62 = "Out-ObfuscatedForEachStatementAst " nocase ascii wide
                        $string63 = "Out-ObfuscatedForStatementAst " nocase ascii wide
                        $string64 = "Out-ObfuscatedFunctionDefinitionAst " nocase ascii wide
                        $string65 = "Out-ObfuscatedFunctionMemberAst " nocase ascii wide
                        $string66 = "Out-ObfuscatedHashtableAst " nocase ascii wide
                        $string67 = "Out-ObfuscatedIfStatementAst " nocase ascii wide
                        $string68 = "Out-ObfuscatedIndexExpressionAst " nocase ascii wide
                        $string69 = "Out-ObfuscatedInvokeMemberExpressionAst " nocase ascii wide
                        $string70 = "Out-ObfuscatedLabeledStatementAst " nocase ascii wide
                        $string71 = "Out-ObfuscatedLoopStatementAst " nocase ascii wide
                        $string72 = "Out-ObfuscatedMemberAst " nocase ascii wide
                        $string73 = "Out-ObfuscatedMemberExpressionAst " nocase ascii wide
                        $string74 = "Out-ObfuscatedMergingRedirectionAst " nocase ascii wide
                        $string75 = "Out-ObfuscatedNamedAttributeArgumentAst " nocase ascii wide
                        $string76 = "Out-ObfuscatedNamedBlockAst " nocase ascii wide
                        $string77 = "Out-ObfuscatedParamBlockAst " nocase ascii wide
                        $string78 = "Out-ObfuscatedParameterAst " nocase ascii wide
                        $string79 = "Out-ObfuscatedParenExpressionAst " nocase ascii wide
                        $string80 = "Out-ObfuscatedPipelineAst " nocase ascii wide
                        $string81 = "Out-ObfuscatedPipelineBaseAst " nocase ascii wide
                        $string82 = "Out-ObfuscatedPropertyMemberAst " nocase ascii wide
                        $string83 = "Out-ObfuscatedRedirectionAst " nocase ascii wide
                        $string84 = "Out-ObfuscatedReturnStatementAst " nocase ascii wide
                        $string85 = "Out-ObfuscatedScriptBlockAst " nocase ascii wide
                        $string86 = "Out-ObfuscatedScriptBlockExpressionAst " nocase ascii wide
                        $string87 = "Out-ObfuscatedStatementAst " nocase ascii wide
                        $string88 = "Out-ObfuscatedStatementBlockAst " nocase ascii wide
                        $string89 = "Out-ObfuscatedStringCommand" nocase ascii wide
                        $string90 = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
                        $string91 = "Out-ObfuscatedStringConstantExpressionAst " nocase ascii wide
                        $string92 = "Out-ObfuscatedSubExpressionAst " nocase ascii wide
                        $string93 = "Out-ObfuscatedSwitchStatementAst " nocase ascii wide
                        $string94 = "Out-ObfuscatedThrowStatementAst " nocase ascii wide
                        $string95 = "Out-ObfuscatedTokenCommand" nocase ascii wide
                        $string96 = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
                        $string97 = "Out-ObfuscatedTrapStatementAst " nocase ascii wide
                        $string98 = "Out-ObfuscatedTryStatementAst " nocase ascii wide
                        $string99 = "Out-ObfuscatedTypeConstraintAst " nocase ascii wide
                        $string100 = "Out-ObfuscatedTypeDefinitionAst " nocase ascii wide
                        $string101 = "Out-ObfuscatedTypeExpressionAst " nocase ascii wide
                        $string102 = "Out-ObfuscatedUnaryExpressionAst " nocase ascii wide
                        $string103 = "Out-ObfuscatedUsingExpressionAst " nocase ascii wide
                        $string104 = "Out-ObfuscatedUsingStatementAst " nocase ascii wide
                        $string105 = "Out-ObfuscatedVariableExpressionAst " nocase ascii wide
                        $string106 = "Out-ObfuscatedWhileStatementAst " nocase ascii wide
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