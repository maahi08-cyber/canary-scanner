# Canary Scanner - Architecture Documentation
============================================

This document provides a comprehensive overview of the Canary Scanner architecture, design decisions, and component interactions.

## 📋 Table of Contents

- [System Overview](#system-overview)
- [Architecture Principles](#architecture-principles)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Security Design](#security-design)
- [Performance Considerations](#performance-considerations)
- [Extensibility](#extensibility)
- [Deployment Architecture](#deployment-architecture)

## 🎯 System Overview

Canary Scanner is a production-ready secret detection tool designed with security, performance, and maintainability in mind. It follows a layered architecture that separates concerns and enables easy testing and extension.

### Core Capabilities
- **Multi-confidence Detection**: Three-tier confidence system (High/Medium/Low)
- **Entropy Analysis**: Shannon entropy for false positive reduction
- **CI/CD Integration**: Native GitHub Actions support with proper exit codes
- **Containerization**: Docker-first design for consistent deployment
- **Pattern Management**: YAML-based configuration with validation

### Design Goals
1. **Security First**: Secure by default with comprehensive input validation
2. **Performance**: Optimized for large repositories with intelligent filtering
3. **Maintainability**: Clean separation of concerns and comprehensive documentation
4. **Extensibility**: Plugin-friendly architecture for custom patterns and outputs
5. **Reliability**: Robust error handling and graceful degradation

## 🏗️ Architecture Principles

### 1. Separation of Concerns
Each component has a single, well-defined responsibility:
- **CLI Layer**: User interface and argument processing
- **Core Engine**: Secret detection logic and orchestration
- **Pattern Management**: Configuration loading and regex compilation
- **Data Models**: Structured data representation

### 2. Dependency Inversion
High-level modules don't depend on low-level modules. Both depend on abstractions:
```python
# Good: Scanner depends on Pattern abstraction
class Scanner:
    def __init__(self, patterns: List[Pattern]):
        self.patterns = patterns

# Pattern loading is separate from scanning logic
patterns = load_patterns("patterns.yml")
scanner = Scanner(patterns)
```

### 3. Immutable Data Structures
Core data models are immutable for thread safety and predictability:
```python
@dataclass(frozen=True)
class Finding:
    file_path: str
    line_number: int
    # ... other fields
```

### 4. Fail-Fast Design
Input validation and error detection happen as early as possible:
- Pattern validation during loading (not during scanning)
- File system checks before processing
- Comprehensive argument validation

## 🔧 Component Architecture

### Layer 1: CLI Interface (canary.py)

**Responsibilities:**
- Command-line argument parsing and validation
- User interface and output formatting  
- Process orchestration and error handling
- Exit code management for CI/CD integration

**Key Components:**
```python
def main():
    """Main entry point with comprehensive error handling"""

def create_argument_parser():
    """Configure command-line interface"""

def display_results():
    """Format and display scan results"""

def determine_exit_code():
    """Calculate appropriate exit code for CI/CD"""
```

**Design Decisions:**
- Uses `argparse` for robust command-line handling
- Rich library for beautiful terminal output
- Separate JSON output mode for automation
- Comprehensive error handling with specific exit codes

### Layer 2: Core Scanning Engine (scanner/core.py)

**Responsibilities:**
- File and directory traversal with intelligent filtering
- Secret detection using compiled regex patterns
- Entropy analysis for false positive reduction
- Finding aggregation and statistics collection

**Key Components:**
```python
class Scanner:
    """Main scanning orchestrator"""

    def scan_file(self, file_path: str) -> Iterator[Finding]:
        """Scan single file with performance optimizations"""

    def scan_directory(self, dir_path: str) -> List[Finding]:
        """Recursively scan directory with filtering"""

    def calculate_entropy(self, text: str) -> float:
        """Shannon entropy analysis for secret validation"""

@dataclass(frozen=True)  
class Finding:
    """Immutable finding representation"""
```

**Design Decisions:**
- Iterator pattern for memory-efficient file processing
- Three-tier confidence system with different validation levels
- Intelligent binary file detection to avoid processing non-text files
- Statistics collection for monitoring and debugging

### Layer 3: Pattern Management (scanner/patterns.py)

**Responsibilities:**
- YAML configuration file loading and parsing
- Regex pattern compilation and validation
- Pattern metadata management
- Error reporting and recovery

**Key Components:**
```python
@dataclass(frozen=True)
class Pattern:
    """Immutable pattern representation with compiled regex"""

def load_patterns(file_path: str) -> List[Pattern]:
    """Load and validate patterns from YAML configuration"""

def validate_patterns_file(file_path: str) -> dict:
    """Validate patterns without full loading"""
```

**Design Decisions:**
- YAML for human-readable configuration
- Pattern compilation at load time for performance
- Comprehensive validation with detailed error messages
- Recovery from partial pattern failures

### Layer 4: Configuration (patterns.yml)

**Structure:**
```yaml
- rule_id: "SERVICE-001"      # Unique identifier
  description: "Human readable"  # User-facing description
  regex: 'pattern'           # Detection regex
  confidence: "High"         # Risk level
```

**Categories:**
- **High Confidence**: Service-specific patterns (AWS keys, GitHub tokens)
- **Medium Confidence**: Broader patterns with light validation
- **Low Confidence**: Generic patterns with strict entropy validation

## 🔄 Data Flow

### 1. Initialization Flow
```
CLI Arguments → Argument Parsing → Environment Validation
    ↓
Pattern Loading → YAML Parsing → Regex Compilation
    ↓
Scanner Initialization → Pattern Organization → Ready State
```

### 2. Scanning Flow
```
Target Path → File/Directory Detection → Traversal Strategy
    ↓
File Processing → Binary Detection → Text Extraction
    ↓
Pattern Matching → Confidence-Based Processing → Entropy Validation
    ↓
Finding Creation → Aggregation → Result Formatting
```

### 3. CI/CD Integration Flow
```
Git Event → Workflow Trigger → Docker Build
    ↓
Container Execution → Scan Processing → Result Analysis
    ↓
Security Gate → Status Check → PR Comment/Merge Decision
```

## 🔒 Security Design

### Input Validation
- **File Path Sanitization**: Prevents directory traversal attacks
- **Regex Validation**: Prevents ReDoS (Regular Expression Denial of Service)
- **Memory Limits**: Protects against resource exhaustion

### Secret Handling
- **Automatic Masking**: Secrets masked in output by default
- **No Persistence**: Secrets never stored on disk
- **Memory Cleanup**: Sensitive data cleared from memory promptly

### Container Security
- **Non-Root Execution**: All operations run as unprivileged user
- **Minimal Base Image**: Reduces attack surface
- **Read-Only Filesystems**: Where possible, use read-only mounts

### CI/CD Security
- **Least Privilege**: Workflow permissions limited to required scopes
- **Secret Masking**: GitHub automatically masks secrets in logs
- **Artifact Encryption**: Scan results encrypted in transit and at rest

## ⚡ Performance Considerations

### Scanning Optimizations

#### 1. Pattern Processing Order
```python
# Process high-confidence patterns first (fastest)
for pattern in self.high_confidence_patterns:
    # No entropy validation needed

# Medium confidence with light validation  
for pattern in self.medium_confidence_patterns:
    if self.is_likely_secret(match, min_entropy=3.5):

# Low confidence with strict validation
for pattern in self.low_confidence_patterns:
    if self.is_likely_secret(match, min_entropy=4.5):
```

#### 2. File System Optimizations
- **Binary Detection**: Skip non-text files early
- **Directory Filtering**: Skip irrelevant directories (node_modules, .git)
- **Memory Efficiency**: Process files line-by-line, not loading entire files

#### 3. Regex Optimizations
- **Pre-compilation**: All patterns compiled at load time
- **Anchoring**: Patterns optimized for early rejection
- **Complexity Limits**: Prevent ReDoS attacks

### Memory Management
- **Iterator Pattern**: Files processed as streams, not loaded entirely
- **Lazy Evaluation**: Patterns only applied when needed
- **Garbage Collection**: Explicit cleanup of large objects

### Performance Benchmarks
- **Small Repository** (< 100 files): 1-3 seconds
- **Medium Repository** (100-1000 files): 5-15 seconds
- **Large Repository** (1000+ files): 30-60 seconds
- **Very Large Repository** (10000+ files): 2-5 minutes

## 🔧 Extensibility

### Adding New Patterns
```yaml
# Add to patterns.yml
- rule_id: MYSERVICE-001
  description: "My Service API Key"
  regex: 'myservice_[a-zA-Z0-9]{32}'
  confidence: "High"
```

### Custom Output Formats
```python
# Extend display_results function
def display_results(findings, output_format="console"):
    if output_format == "xml":
        return generate_xml_output(findings)
    elif output_format == "csv":
        return generate_csv_output(findings)
```

### Custom Entropy Algorithms
```python
# Extend Scanner class
class AdvancedScanner(Scanner):
    def calculate_entropy(self, text: str) -> float:
        # Implement custom entropy calculation
        return custom_entropy_algorithm(text)
```

### Plugin Architecture (Future)
```python
# Planned plugin interface
class ScannerPlugin:
    def pre_scan_hook(self, scanner: Scanner) -> None:
        pass

    def post_finding_hook(self, finding: Finding) -> Finding:
        pass
```

## 🚀 Deployment Architecture

### Local Development
```
Developer Machine
├── Python 3.11+
├── Virtual Environment
└── Direct Execution
```

### CI/CD Pipeline
```
GitHub Repository
├── Workflow Trigger
├── Docker Build (Multi-stage)
├── Container Execution
├── Result Processing
└── Security Gate Decision
```

### Container Architecture
```
Multi-Stage Docker Build
├── Builder Stage (Dependencies)
│   ├── Python 3.11-slim
│   ├── System Dependencies
│   └── Python Package Installation
└── Production Stage (Runtime)
    ├── Minimal Base Image
    ├── Non-Root User
    ├── Application Code
    └── Health Checks
```

### Integration Points

#### GitHub Actions Integration
- **Trigger Events**: Push, PR, manual dispatch
- **Job Dependencies**: Build → Scan → Gate → Cleanup  
- **Artifact Management**: Results stored and retrievable
- **Status Reporting**: PR comments and check status

#### Docker Registry Integration
- **Image Storage**: GitHub Container Registry (ghcr.io)
- **Versioning**: Semantic versioning with git tags
- **Security Scanning**: Container vulnerability scanning

#### Monitoring Integration (Future)
- **Metrics Collection**: Prometheus metrics
- **Alerting**: PagerDuty/Slack integration
- **Dashboards**: Grafana visualization

## 📊 Quality Attributes

### Reliability
- **Error Handling**: Comprehensive exception handling
- **Graceful Degradation**: Continues scanning even if individual files fail
- **Resource Management**: Proper cleanup and resource limits

### Maintainability  
- **Clean Architecture**: Clear separation of concerns
- **Documentation**: Comprehensive inline and external documentation
- **Testing Strategy**: Unit, integration, and end-to-end tests

### Scalability
- **Horizontal Scaling**: Multiple scanner instances in CI/CD
- **Vertical Scaling**: Efficient memory and CPU usage
- **Load Distribution**: Docker swarm/Kubernetes ready

### Security
- **Threat Modeling**: Regular security assessments
- **Vulnerability Management**: Dependency scanning and updates
- **Access Control**: Principle of least privilege

## 🔮 Future Architecture Considerations

### Phase 3 Enhancements
- **Web Dashboard**: React-based results visualization
- **Historical Analysis**: Trend analysis and reporting
- **Advanced Alerting**: Integration with security orchestration platforms

### Microservices Evolution
- **Scanner Service**: Core detection engine
- **Pattern Service**: Dynamic pattern management
- **Results Service**: Historical data and analytics
- **Notification Service**: Multi-channel alerting

### Cloud-Native Features
- **Kubernetes Operators**: Custom resource definitions
- **Service Mesh**: Istio integration for observability
- **Event-Driven Architecture**: Kafka/NATS messaging

---

This architecture provides a solid foundation for current requirements while maintaining flexibility for future enhancements and scale.
