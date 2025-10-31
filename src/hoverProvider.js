const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

class ASMHoverProvider {
    constructor() {
        this.docs = this.loadFunctionDocs();
    }

    loadFunctionDocs() {
        try {
            const docsPath = path.join(__dirname, '..', 'data', 'function-docs.json');
            const rawData = fs.readFileSync(docsPath, 'utf8');
            return JSON.parse(rawData);
        } catch (error) {
            console.error('Failed to load function docs:', error);
            return {};
        }
    }

    // 新增方法：获取所有函数名
    getFunctionNames() {
        return Object.keys(this.docs);
    }

    provideHover(document, position, token) {
        const range = document.getWordRangeAtPosition(position);
        const word = document.getText(range);
        
        if (this.docs[word]) {
            const doc = this.docs[word];
            const markdown = new vscode.MarkdownString();
            
            // 修正：使用正确的换行符和转义
            markdown.appendMarkdown(`### ${word}\n\n`);
            markdown.appendMarkdown(`**${doc.description}**\n\n`);
            markdown.appendMarkdown(`${doc.details}\n\n`);
            markdown.appendMarkdown(`**Syntax :** \`${doc.syntax}\`\n\n`);
            markdown.appendMarkdown(`**Example :** \`${doc.example}\``);
            
            return new vscode.Hover(markdown);
        }
        
        return null;
    }
}

module.exports = ASMHoverProvider;