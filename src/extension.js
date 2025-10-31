const vscode = require('vscode');
const ASMHoverProvider = require('./hoverProvider');
const fs = require('fs');
const path = require('path'); // 确保导入 path 模块

function activate(context) {
    console.log('ASM extension is now active!');

    const hoverProvider = new ASMHoverProvider();
    
    // 动态更新语法文件
    updateSyntaxFile(hoverProvider.getFunctionNames());
    
    // 注册悬停提供程序
    const hoverDisposable  = vscode.languages.registerHoverProvider('asm', new ASMHoverProvider());
    context.subscriptions.push(hoverDisposable );
}

function updateSyntaxFile(functionNames) {
    const syntaxPath = path.join(__dirname, '..', 'syntaxes', 'asm.tmLanguage.json');
    
    // 构建正则表达式模式
    const functionPattern = `\\b(${functionNames.join('|')})\\b`;
    
    const syntaxTemplate = {
        "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
        "name": "ASM",
        "patterns": [
            {
                "include": "#keywords"
            },
            {
                "include": "#functions"
            },
            {
                "include": "#strings"
            }
        ],
        "repository": {
            "keywords": {
                "patterns": [{
                    "name": "keyword.control.asm",
                    "match": "\\b(if|while|for|return)\\b"
                }]
            },
            "functions": {
                "patterns": [{
                    "name": "support.function.directive.asm",
                    "match": functionPattern
                }]
            },
            "strings": {
                "name": "string.quoted.double.asm",
                "begin": "\"",
                "end": "\"",
                "patterns": [{
                    "name": "constant.character.escape.asm",
                    "match": "\\\\."
                }]
            }
        },
        "scopeName": "source.asm"
    };
    
    // 写入更新后的语法文件
    fs.writeFileSync(syntaxPath, JSON.stringify(syntaxTemplate, null, 2));
    console.log('Syntax file updated with functions:', functionNames);
}

function deactivate() {
    console.log('ASM extension is now deactivated!');
}

module.exports = {
    activate,
    deactivate
};