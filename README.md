# LGPD Compliance Auditor

Auditor tecnico de codigo fonte para conformidade com a Lei Geral de Protecao de Dados Pessoal (Lei 13.709/2018).

Ferramenta agnostica de tecnologia desenvolvida para analisar aplicacoes de software, mapear dados pessoais (ROPA) e identificar vulnerabilidades tecnicas de privacidade diretamente no codigo fonte.

---

## Sumario

1. Visao Geral
2. Principais Funcionalidades
3. Metodologia de Analise e Reducao de Alucinacoes
4. Matriz de Auditoria da Lei 13.709
5. Requisitos do Sistema
6. Como Utilizar a Skill
7. Utilizacao via Linha de Comando
8. Arquivo de Governanca Local (.lgpdrc)
9. Exemplo de Relatorio Gerado
10. Estrutura do Repositorio
11. Licenca

---

## 1. Visao Geral

A maioria dos programas de conformidade com a LGPD limita se a revisoes juridicas de contratos e politicas de privacidade publicadas em sites. No entanto, o verdadeiro risco de violacao reside no codigo fonte da aplicacao:
• Schemas de banco de dados sem protecao em dados sensiveis
• Impressao de dados pessoais e credenciais em arquivos de log
• Formularios com caixas de consentimento pre marcadas
• Exclusao logica simples (soft delete) mantendo dados indefinidamente
• Scripts rastreadores de terceiros injetados sem opt in previo

O LGPD Compliance Auditor atua como um auditor tecnico automatizado que opera em duas camadas: um scanner estatico de alta velocidade baseado unicamente na biblioteca padrao do Python e um motor de avaliacao semantica baseado em evidencias estritas para eliminar falsos positivos e alucinacoes.

---

## 2. Principais Funcionalidades

| Funcionalidade | Descricao Tecnica |
| :--- | :--- |
| Agnostico de Tecnologia | Analisa repositórios em qualquer stack: TypeScript, JavaScript, Python, Java, Go, C#, PHP, Ruby, SQL ou schemas NoSQL |
| Zero Dependencias Externas | O scanner auxiliar utiliza exclusivamente a biblioteca padrao do Python, sem necessidade de pip install |
| Modo Hibrido Resiliente | Executa primariamente o script auxiliar de alta velocidade e possui procedimento autonomo completo para operacao em sandboxes |
| Baseado em Evidencias Estritas | Nao emite apontamentos teoricos. Toda vulnerabilidade exige a citacao literal do trecho de codigo, arquivo e linha fisica |
| Governanca via .lgpdrc | Suporta arquivo local de configuracao para cadastrar dados do Encarregado (DPO), termos customizados e supressoes homologadas |
| Relatorio Executivo e Tecnico | Produz um diagnostico estruturado em tabelas contendo Score de Conformidade (0 a 100), ROPA e Plano de Remediacao |

---

## 3. Metodologia de Analise e Reducao de Alucinacoes

Para assegurar auditorias precisas e impedir que a inteligencia artificial suponha ou crie vulnerabilidades ficticias, a skill adota uma metodologia formal inspirada nas normas ISO/IEC 27550 (Engenharia de Privacidade) e no framework LINDDUN de modelagem de ameacas:

### Pilares da Metodologia

| Pilar Metodologico | Principio Aplicado | Como Opera na Pratica |
| :--- | :--- | :--- |
| Grounding em Evidencias Estritas | Evidence Based Verification | E expressamente proibido relatar qualquer gap sem comprovar o trecho exato de codigo, arquivo e linha fisica existente |
| Falsificacao em Duas Etapas | Dual Pass Triage | Primeiro passo: coleta de candidatos suspeitos. Segundo passo: busca ativa por camadas de defesa (bcrypt, sanitizadores, proxies) para refutar a hipotese de risco |
| Catalogo Fechado de Regras | Constrained Catalog | A analise e restrita aos artigos e incisos canonicos da Lei 13.709, impedindo reinterpretacoes juridicas arbitrarias |
| Deducao Matematica Transparente | Deterministic Scoring | A pontuacao de 0 a 100 e calculada por deducao aritmetica fixa (Critico menos 15, Alto menos 8, Medio menos 3, Informativo menos 1) |

### Fluxo Operacional da Metodologia

1. Fase Heuristica Factual: O script `scanner.py` percorre os arquivos do repositorio extraindo ocorrencias literais de termos de dados pessoais, chamadas de logging e elementos de formulario.
2. Fase de Verificacao Defensiva: O modelo avalia se a ocorrencia possui tratamento de mitigacao (hashing em senhas, mascaramento de log por proxy, consentimento ativo). Caso exista protecao, o apontamento e descartado como falso positivo.
3. Fase de Integracao de Governanca: Verifica se o arquivo `.lgpdrc` possui justificativa registrada pelo Encarregado (DPO) para o item. Se homologado, o item e registrado como risco mitigado sem penalizacao do score.
4. Fase de Sintese Normativa: Consolidacao dos gaps remanescentes, enquadramento nos artigos oficiais e geracao do plano de remediacao.

---

## 4. Matriz de Auditoria da Lei 13.709

A auditoria cobre 7 eixos essenciais de engenharia de privacidade:

| Eixo de Inspecao | Base Legal | Foco da Varredura no Codigo |
| :--- | :--- | :--- |
| 1. Inventario de PII e Dados Sensiveis | Artigo 5 e Artigo 11 | Campos de dados pessoais comuns e dados sensiveis (saude, biometria, religiao, raca) em modelos, tabelas e DTOs |
| 2. Seguranca em Logs e Telemetria | Artigo 6 (Inciso VII) e Artigo 46 | Chamadas de log e saidas de console recebendo objetos de requisicao ou credenciais sem mascara |
| 3. Consentimento Livre | Artigo 8 (Paragrafo 4) | Caixas de selecao de termos ou marketing configuradas com estado ativo por padrao em formularios |
| 4. Direitos do Titular (DSR) | Artigo 18 | Existencia de rotas para exportacao de dados em formato legivel e exclusao de perfil |
| 5. Retencao e Anonimizacao | Artigo 16 | Uso de exclusao logica (soft delete) sem rotinas programadas de anonimizacao ou expurgo |
| 6. Seguranca da Informacao | Artigo 46 | Conferencia de uso de algoritmos fortes de hash para senhas e criptografia em dados sensiveis |
| 7. Provedores Terceiros e DPO | Artigos 33 e 41 | Scripts de analytics carregados sem bloqueio previo e canal publico para contato com o Encarregado |

---

## 5. Requisitos do Sistema

1. Python 3.8 ou superior (apenas modulos padrao: os, sys, re, json, fnmatch, argparse, pathlib)
2. Sistema Operacional: Linux, macOS ou Windows
3. Nao requer privilegios administrativos para execucao

---

## 6. Como Utilizar a Skill

A skill suporta acionamento direto por comandos de barra (slash commands) e por linguagem natural:

### Gatilhos e Comandos Dedicados

| Comando / Gatilho | Escopo de Execucao | Saida Gerada |
| :--- | :--- | :--- |
| /lgpd-audit | Varredura completa nos 7 eixos da LGPD | Sumario Executivo, Scorecard de Risco (0 a 100), Matriz de Gaps e Plano de Remediacao |
| /lgpd-pii | Inspecao focada em modelos, schemas e DTOs | Inventario formal de dados pessoais (ROPA) com classificacao de sensibilidade e base legal |
| /lgpd-fix [alvo] | Remediacao cirurgica de uma vulnerabilidade | Alteracao com menor diff possivel (mascaramento de log, remocao de defaultChecked, etc) |

### Exemplos de Acionamento via Comandos

```text
/lgpd-audit
```

```text
/lgpd-pii
```

```text
/lgpd-fix tests/fixtures/sample_app/auth_controller.ts:5
```

### Exemplos de Acionamento via Linguagem Natural

```text
Faca uma auditoria de conformidade LGPD nesta aplicacao
```

```text
Gere o inventario de dados pessoais (ROPA) deste repositorio
```

```text
Corrija o vazamento de log apontado no arquivo auth_controller.ts linha 5
```

---

## 7. Utilizacao via Linha de Comando

O script auxiliar pode ser executado diretamente em seu terminal ou em esteiras de integracao continua (CI):

Para varrer o diretorio atual:
```bash
python3 scripts/scanner.py
```

Para varrer um projeto em diretorio especifico:
```bash
python3 scripts/scanner.py --dir /caminho/do/projeto
```

Para informar um arquivo de configuracao customizado:
```bash
python3 scripts/scanner.py --dir /caminho/do/projeto --config /caminho/.lgpdrc
```

Para gravar o resultado em arquivo JSON:
```bash
python3 scripts/scanner.py --dir /caminho/do/projeto --output resultado_lgpd.json
```

---

## 8. Arquivo de Governanca Local (.lgpdrc)

Voce pode posicionar um arquivo `.lgpdrc` ou `.lgpdrc.json` na raiz da sua aplicacao para alinhar a analise tecnica com as diretrizes do setor juridico da empresa:

```json
{
  "dpo": {
    "name": "Nome do Encarregado de Dados",
    "email": "dpo@empresa.com.br",
    "channel_url": "https://empresa.com.br/privacidade"
  },
  "custom_pii": [
    "matricula_funcional",
    "numero_beneficio",
    "registro_geral"
  ],
  "custom_sensitive": [
    "laudo_clinico",
    "medicamento_prescrito"
  ],
  "ignore_paths": [
    "database/seeds/**",
    "tests/mocks/**"
  ],
  "suppressions": [
    {
      "file": "src/controllers/auth.ts",
      "line": 5,
      "reason": "Payload devidamente sanitizado por middleware antes do log",
      "approved_by": "dpo@empresa.com.br"
    }
  ]
}
```

### Efeito dos Campos de Configuracao

| Campo | Finalidade |
| :--- | :--- |
| dpo | Comprova o atendimento ao Artigo 41 da LGPD, registrando o canal oficial de comunicacao |
| custom_pii | Incorpora termos de dados pessoais comuns exclusivos do seu modelo de negocio |
| custom_sensitive | Incorpora termos de dados pessoais sensiveis especificos do seu setor de atuacao |
| ignore_paths | Pula pastas de teste, dados ficticios ou codigos legados fora de operacao |
| suppressions | Registra supressoes com aval do DPO, evitando penalizacoes indevidas no score |

---

## 9. Exemplo de Relatorio Gerado

Ao executar a auditoria em uma aplicacao, a saida segue o modelo formal estruturado:

### Relatorio de Conformidade LGPD
Auditoria Tecnica de Software | Lei 13.709/2018

### Sumario Executivo de Conformidade

| Indicador | Avaliacao | Status |
| :--- | :--- | :--- |
| Pontuacao Geral de Conformidade | 71 de 100 pontos | Nivel Moderado de Risco |
| Total de Entidades com Dados Pessoais | 3 estruturas mapeadas | Requer Controle de Acesso |
| Dados Pessoais Sensiveis (Artigo 11) | 2 campos identificados | Atencao Imediata |
| Falhas Criticas de Seguranca | 1 ocorrencia | Correcao Prioritaria |
| Falhas de Media e Alta Severidade | 2 ocorrencias | Planejamento de Correcao |

### 1. Inventario de Dados Pessoais e Mapeamento de Risco (ROPA)

| Entidade ou Tabela | Campo Mapeado | Classificacao Legal | Estado de Protecao | Risco Apurado |
| :--- | :--- | :--- | :--- | :--- |
| usuarios | email | Dado Pessoal Comum | Texto Puro | Baixo |
| usuarios | cpf | Dado Pessoal Comum | Texto Puro sem Criptografia | Medio |
| usuarios | hash_senha | Credencial de Acesso | Protegido por Algoritmo de Hash | Adequado |
| prontuarios | diagnostico_medico | Dado Pessoal Sensivel (Artigo 11) | Texto Puro no Banco de Dados | Critico |

### 2. Matriz de Vulnerabilidades e Gaps Detectados

| Severidade | Artigo da Lei | Localizacao no Codigo | Diagnostico Tecnico | Acao de Remediacao |
| :--- | :--- | :--- | :--- | :--- |
| CRITICO | Artigo 6, Inciso VII e Artigo 46 | src/controllers/auth.ts linha 54 | Impressao de payload completo em arquivo de log contendo credenciais | Remover injecao direta de objeto no log e aplicar sanitizacao previa |
| ALTO | Artigo 16 e Artigo 18, Inciso VI | src/models/Account.py linha 32 | Exclusao de conta apenas marca campo logico mantendo dados pessoais | Criar rotina programada para sobrescrever campos identificaveis |
| MEDIO | Artigo 8, Paragrafo 4 | web/components/Signup.vue linha 88 | Caixa de selecao para comunicacoes configurada como marcada por padrao | Alterar estado inicial do componente exigindo acao ativa do titular |

### 3. Justificativas e Supressoes Homologadas pelo DPO (.lgpdrc)

| Arquivo e Linha | Achado Original | Justificativa Registrada | Aprovador | Impacto no Score |
| :--- | :--- | :--- | :--- | :--- |
| src/services/audit.go linha 82 | Inspecao de IP | Registro obrigatorio de conexao pelo Artigo 15 do Marco Civil da Internet | dpo@empresa.com.br | Risco Mitigado (Sem Deducao) |

---

## 10. Estrutura do Repositorio

```text
lgpd/
├── SKILL.md
│   Instrucoes operacionais para o agente, catalogo fechado e regras anti alucinacao
│
├── README.md
│   Documentacao tecnica e guia de utilizacao
│
├── .lgpdrc.example
│   Modelo de arquivo de governanca local
│
├── scripts/
│   └── scanner.py
│       Motor agnostico de varredura estatica sem dependencias externas
│
├── skills/
│   ├── lgpd-audit/
│   │   ├── SKILL.md
│   │   └── scripts/scanner.py
│   ├── lgpd-pii/
│   │   ├── SKILL.md
│   │   └── scripts/scanner.py
│   └── lgpd-fix/
│       └── SKILL.md
│
└── tests/
    └── fixtures/
        └── sample_app/
            Aplicacao multilinguagem para testes de regressao e validacao de regras
```

---

## 11. Licenca

Este projeto e disponibilizado sob os termos da licenca MIT.
