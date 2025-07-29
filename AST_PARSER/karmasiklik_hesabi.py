import ast
import sys
from typing import Dict, List, Any, Set
from dataclasses import dataclass


@dataclass
class ComplexityMetrics:
    """Kod karmaşıklığı metriklerini tutan sınıf"""
    cyclomatic_complexity: int = 0  # Döngüsel karmaşıklık
    cognitive_complexity: int = 0   # Bilişsel karmaşıklık
    function_count: int = 0         # Fonksiyon sayısı
    class_count: int = 0           # Sınıf sayısı
    line_count: int = 0            # Satır sayısı
    decision_points: int = 0       # Karar noktaları
    loop_count: int = 0            # Döngü sayısı
    condition_count: int = 0       # Koşul sayısı
    nesting_depth: int = 0         # Maksimum iç içe geçme derinliği
    big_o_complexity: str = "O(1)" # Big-O karmaşıklığı
    recursive_calls: int = 0       # Recursive çağrı sayısı
    nested_loop_depth: int = 0     # İç içe döngü derinliği
    logarithmic_loops: int = 0     # Logaritmik döngü sayısı
    nested_log_depth: int = 0      # İç içe logaritmik döngü derinliği


class ASTComplexityAnalyzer(ast.NodeVisitor):
    """AST üzerinde dolaşarak kod karmaşıklığını hesaplayan sınıf"""
    
    def __init__(self):
        self.metrics = ComplexityMetrics()
        self.current_depth = 0
        self.max_depth = 0
        self.loop_depth = 0
        self.max_loop_depth = 0
        self.log_loop_depth = 0         # Logaritmik döngü derinliği
        self.max_log_depth = 0          # Maksimum logaritmik döngü derinliği
        self.function_complexities = {}  # Her fonksiyon için ayrı karmaşıklık
        self.function_names = set()     # Tanımlanan fonksiyon isimleri
        self.current_function = None
        self.recursive_functions = set() # Recursive fonksiyonlar
        self.loop_variables = {}        # Döngü değişkenlerini takip et
        self.current_loop_vars = []     # Mevcut döngü değişkenleri
        
    def visit_FunctionDef(self, node):
        """Fonksiyon tanımlarını ziyaret et"""
        self.metrics.function_count += 1
        self.function_names.add(node.name)
        
        # Her fonksiyon için ayrı complexity hesapla
        old_function = self.current_function
        old_complexity = self.metrics.cyclomatic_complexity
        old_loop_depth = self.max_loop_depth
        old_log_depth = self.max_log_depth
        
        self.current_function = node.name
        self.max_loop_depth = 0  # Her fonksiyon için sıfırla
        self.max_log_depth = 0   # Logaritmik derinliği de sıfırla
        function_start_complexity = self.metrics.cyclomatic_complexity
        
        # Fonksiyon gövdesini analiz et
        self.generic_visit(node)
        
        # Bu fonksiyonun karmaşıklığını hesapla
        function_complexity = self.metrics.cyclomatic_complexity - function_start_complexity + 1
        self.function_complexities[node.name] = function_complexity
        
        # Her fonksiyon için ayrı nested loop depth kaydet
        if self.max_loop_depth > self.metrics.nested_loop_depth:
            self.metrics.nested_loop_depth = self.max_loop_depth
            
        # Logaritmik döngü derinliğini kaydet
        if self.max_log_depth > self.metrics.nested_log_depth:
            self.metrics.nested_log_depth = self.max_log_depth
            
        self.max_loop_depth = max(self.max_loop_depth, old_loop_depth)
        self.max_log_depth = max(self.max_log_depth, old_log_depth)
        self.current_function = old_function
        
    def visit_AsyncFunctionDef(self, node):
        """Async fonksiyon tanımlarını ziyaret et"""
        self.visit_FunctionDef(node)
        
    def visit_ClassDef(self, node):
        """Sınıf tanımlarını ziyaret et"""
        self.metrics.class_count += 1
        self.generic_visit(node)
        
    def visit_Call(self, node):
        """Fonksiyon çağrılarını ziyaret et (recursive detection için)"""
        if isinstance(node.func, ast.Name):
            # Eğer çağrılan fonksiyon, şu an içinde bulunduğumuz fonksiyonsa
            if (self.current_function and 
                node.func.id == self.current_function):
                self.recursive_functions.add(self.current_function)
                self.metrics.recursive_calls += 1
        self.generic_visit(node)
        
    def visit_If(self, node):
        """If ifadelerini ziyaret et"""
        self.metrics.cyclomatic_complexity += 1
        self.metrics.decision_points += 1
        self.metrics.condition_count += 1
        self._enter_block()
        self.generic_visit(node)
        self._exit_block()
        
    def visit_While(self, node):
        """While döngülerini ziyaret et"""
        self.metrics.cyclomatic_complexity += 1
        self.metrics.loop_count += 1
        self.metrics.decision_points += 1
        
        # Döngü değişkenlerini tespit et
        loop_vars = self._extract_loop_variables(node)
        self.current_loop_vars.append(loop_vars)
        
        # Logaritmik döngü kontrolü için gövdeyi ön-analiz et
        is_logarithmic = self._pre_check_logarithmic_loop(node, loop_vars)
        
        self._enter_block()
        self._enter_loop()
        
        # Eğer logaritmikse, logaritmik döngü derinliğine gir
        if is_logarithmic:
            self.metrics.logarithmic_loops += 1
            self._enter_log_loop()
        
        # Döngü gövdesini analiz et
        self.generic_visit(node)
        
        # Logaritmik döngüden çık
        if is_logarithmic:
            self._exit_log_loop()
        
        self._exit_loop()
        self._exit_block()
        self.current_loop_vars.pop()
        
    def visit_For(self, node):
        """For döngülerini ziyaret et"""
        self.metrics.cyclomatic_complexity += 1
        self.metrics.loop_count += 1
        self.metrics.decision_points += 1
        self._enter_block()
        self._enter_loop()
        self.generic_visit(node)
        self._exit_loop()
        self._exit_block()
        
    def visit_Try(self, node):
        """Try-except bloklarını ziyaret et"""
        self.metrics.cyclomatic_complexity += 1
        self.metrics.decision_points += 1
        
        # Her except bloğu için ayrı karmaşıklık
        for handler in node.handlers:
            self.metrics.cyclomatic_complexity += 1
            self.metrics.decision_points += 1
            
        self._enter_block()
        self.generic_visit(node)
        self._exit_block()
        
    def visit_With(self, node):
        """With ifadelerini ziyaret et"""
        self.metrics.cyclomatic_complexity += 1
        self._enter_block()
        self.generic_visit(node)
        self._exit_block()
        
    def visit_AsyncWith(self, node):
        """Async with ifadelerini ziyaret et"""
        self.visit_With(node)
        
    def visit_BoolOp(self, node):
        """Boolean operatörlerini ziyaret et (and, or)"""
        # Her ek boolean operatör karmaşıklığı artırır
        if isinstance(node.op, (ast.And, ast.Or)):
            self.metrics.cyclomatic_complexity += len(node.values) - 1
            self.metrics.condition_count += len(node.values) - 1
        self.generic_visit(node)
        
    def visit_ListComp(self, node):
        """List comprehension'ları ziyaret et"""
        self.metrics.cyclomatic_complexity += len(node.generators)
        for generator in node.generators:
            if generator.ifs:
                self.metrics.cyclomatic_complexity += len(generator.ifs)
        self.generic_visit(node)
        
    def visit_DictComp(self, node):
        """Dict comprehension'ları ziyaret et"""
        self.visit_ListComp(node)
        
    def visit_SetComp(self, node):
        """Set comprehension'ları ziyaret et"""
        self.visit_ListComp(node)
        
    def visit_GeneratorExp(self, node):
        """Generator expression'ları ziyaret et"""
        self.visit_ListComp(node)
        
    def visit_AugAssign(self, node):
        """Artırılmış atama operatörlerini ziyaret et (*=, /=, +=, vb.)"""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            
            # Operatör tipini belirle
            op_type = None
            if isinstance(node.op, ast.Mult):
                op_type = '*='
            elif isinstance(node.op, ast.Div):
                op_type = '/='
            elif isinstance(node.op, ast.FloorDiv):
                op_type = '//='
            elif isinstance(node.op, ast.Pow):
                op_type = '**='
            elif isinstance(node.op, ast.Add):
                op_type = '+='
            elif isinstance(node.op, ast.Sub):
                op_type = '-='
                
            # Değişken operasyon geçmişini kaydet
            if var_name not in self.loop_variables:
                self.loop_variables[var_name] = []
            if op_type:
                self.loop_variables[var_name].append(op_type)
                
        self.generic_visit(node)
        
    def _enter_block(self):
        """Bir blok içine girerken derinliği artır"""
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        
    def _exit_block(self):
        """Bir bloktan çıkarken derinliği azalt"""
        self.current_depth -= 1
        
    def _enter_loop(self):
        """Döngü içine girerken döngü derinliğini artır"""
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        
    def _exit_loop(self):
        """Döngüden çıkarken döngü derinliğini azalt"""
        self.loop_depth -= 1
    
    def _enter_log_loop(self):
        """Logaritmik döngü içine girerken derinliği artır"""
        self.log_loop_depth += 1
        self.max_log_depth = max(self.max_log_depth, self.log_loop_depth)
        
    def _exit_log_loop(self):
        """Logaritmik döngüden çıkarken derinliği azalt"""
        self.log_loop_depth -= 1
        
    def _extract_loop_variables(self, node):
        """Döngü koşulundan değişkenleri çıkar"""
        variables = set()
        if hasattr(node, 'test') and node.test:
            # While döngüsü koşulunu analiz et
            for child in ast.walk(node.test):
                if isinstance(child, ast.Name):
                    variables.add(child.id)
        return variables
    
    def _pre_check_logarithmic_loop(self, node, loop_vars):
        """Döngü gövdesini ön-analiz ederek logaritmik olup olmadığını kontrol et"""
        # Döngü gövdesindeki tüm AugAssign node'larını kontrol et
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign) and isinstance(child.target, ast.Name):
                var_name = child.target.id
                # Döngü değişkenlerinden biri çarpma/bölme ile değiştiriliyorsa logaritmik
                if var_name in loop_vars:
                    if isinstance(child.op, (ast.Mult, ast.Div, ast.FloorDiv, ast.Pow)):
                        return True
        return False
        
    def _check_logarithmic_loop(self, loop_vars):
        """Döngünün logaritmik olup olmadığını kontrol et (eski metod - kullanılmıyor)"""
        # Döngü gövdesinde logaritmik artış aramak için
        # Önceki döngü içeriğinde bu değişkenlerin *= veya /= ile 
        # değiştirilip değiştirilmediğini kontrol edeceğiz
        for var in loop_vars:
            if var in self.loop_variables:
                operations = self.loop_variables[var]
                # Çarpma veya bölme işlemi varsa logaritmik kabul et
                if any(op in ['*=', '/=', '//=', '**='] for op in operations):
                    return True
        return False
        
    def _calculate_big_o(self):
        """Big-O karmaşıklığını hesapla"""
        # Recursive fonksiyonlar varsa
        if self.metrics.recursive_calls > 0:
            if self.metrics.nested_loop_depth > 0 or self.metrics.nested_log_depth > 0:
                return "O(n^k * 2^n)"  # Recursive + loops  
            return "O(2^n)"  # Sadece recursive
        
        # Logaritmik döngüler öncelikli - nested_log_depth kullan
        if self.metrics.nested_log_depth > 0:
            if self.metrics.nested_log_depth >= 3:
                return "O(log³ n)"
            elif self.metrics.nested_log_depth == 2:
                return "O(log² n)"  # Bu bizim durumumuz!
            elif self.metrics.nested_log_depth == 1:
                # Tek logaritmik döngü
                if self.metrics.nested_loop_depth > self.metrics.nested_log_depth:
                    return "O(n log n)"  # Normal döngü + log döngü
                return "O(log n)"
                
        # Normal iç içe döngü derinliğine göre  
        if self.metrics.nested_loop_depth >= 3:
            return "O(n³)"
        elif self.metrics.nested_loop_depth == 2:
            return "O(n²)"
        elif self.metrics.nested_loop_depth == 1:
            # Tek döngü ama karmaşık işlemler varsa
            if self.metrics.decision_points > 3:
                return "O(n log n)"
            return "O(n)"
        elif self.metrics.loop_count > 0:
            # Döngü var ama iç içe değil
            return "O(n)"
        elif self.metrics.decision_points > 5:
            # Çok fazla karar noktası
            return "O(log n)"
        else:
            # Sadece basit işlemler
            return "O(1)"


class CodeComplexityAnalyzer:
    """Ana kod karmaşıklığı analiz sınıfı"""
    
    def __init__(self):
        self.analyzer = None
        
    def analyze_code(self, code: str) -> ComplexityMetrics:
        """Verilen kod string'ini analiz et"""
        try:
            # Kodu AST'ye çevir
            tree = ast.parse(code)
            
            # Satır sayısını hesapla
            line_count = len([line for line in code.split('\n') if line.strip()])
            
            # AST analiz et
            self.analyzer = ASTComplexityAnalyzer()
            self.analyzer.visit(tree)
            
            # Big-O karmaşıklığını hesapla
            big_o = self.analyzer._calculate_big_o()
            
            # Metrikleri güncelle
            self.analyzer.metrics.line_count = line_count
            self.analyzer.metrics.nesting_depth = self.analyzer.max_depth
            self.analyzer.metrics.big_o_complexity = big_o
            
            # Eğer kod boşsa, cyclomatic complexity en az 1 olmalı
            if self.analyzer.metrics.cyclomatic_complexity == 0:
                self.analyzer.metrics.cyclomatic_complexity = 1
                
            return self.analyzer.metrics
            
        except SyntaxError as e:
            print(f"❌ Syntax Hatası: {e}")
            return ComplexityMetrics()
        except Exception as e:
            print(f"❌ Analiz Hatası: {e}")
            return ComplexityMetrics()
            
    def analyze_file(self, filepath: str) -> ComplexityMetrics:
        """Dosyadan kod okuyarak analiz et"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                code = file.read()
            return self.analyze_code(code)
        except FileNotFoundError:
            print(f"❌ Dosya bulunamadı: {filepath}")
            return ComplexityMetrics()
        except Exception as e:
            print(f"❌ Dosya okuma hatası: {e}")
            return ComplexityMetrics()
            
    def get_function_complexities(self) -> Dict[str, int]:
        """Her fonksiyon için ayrı karmaşıklık değerlerini döndür"""
        if self.analyzer:
            return self.analyzer.function_complexities
        return {}
        
    def get_recursive_functions(self) -> Set[str]:
        """Recursive fonksiyonları döndür"""
        if self.analyzer:
            return self.analyzer.recursive_functions
        return set()
        
    def print_detailed_report(self, metrics: ComplexityMetrics):
        """Detaylı analiz raporu yazdır"""
        print("\n" + "="*70)
        print("📊 KOD KARMAŞIKLIĞI ANALİZ RAPORU")
        print("="*70)
        
        # Ana metrikler
        print(f"🚀 Big-O Karmaşıklığı: {metrics.big_o_complexity}")
        print(f"🔄 Döngüsel Karmaşıklık (Cyclomatic): {metrics.cyclomatic_complexity}")
        print(f"🔧 Fonksiyon Sayısı: {metrics.function_count}")
        print(f"🏗️  Sınıf Sayısı: {metrics.class_count}")
        print(f"📝 Toplam Satır Sayısı: {metrics.line_count}")
        
        # Döngü ve karar analizi
        print(f"\n🔁 Döngü Analizi:")
        print(f"   • Toplam Döngü: {metrics.loop_count}")
        print(f"   • İç İçe Döngü Derinliği: {metrics.nested_loop_depth}")
        print(f"   • Logaritmik Döngü: {metrics.logarithmic_loops}")
        print(f"   • İç İçe Log Derinliği: {metrics.nested_log_depth}")
        print(f"   • Recursive Çağrı: {metrics.recursive_calls}")
        
        print(f"\n🎯 Karar Analizi:")
        print(f"   • Karar Noktaları: {metrics.decision_points}")
        print(f"   • Koşul Sayısı: {metrics.condition_count}")
        print(f"   • Max İç İçe Geçme Derinliği: {metrics.nesting_depth}")
        
        # Karmaşıklık değerlendirmesi
        complexity_level = self._evaluate_complexity(metrics.cyclomatic_complexity)
        big_o_level = self._evaluate_big_o(metrics.big_o_complexity)
        
        print(f"\n⭐ Değerlendirme:")
        print(f"   • Cyclomatic Seviye: {complexity_level}")
        print(f"   • Big-O Performans: {big_o_level}")
        
        # Recursive fonksiyonlar
        recursive_funcs = self.get_recursive_functions()
        if recursive_funcs:
            print(f"\n🔄 Recursive Fonksiyonlar:")
            for func in recursive_funcs:
                print(f"   • {func}")
        
        # Fonksiyon bazlı karmaşıklık
        function_complexities = self.get_function_complexities()
        if function_complexities:
            print(f"\n🔍 FONKSİYON BAZLI KARMAŞIKLIK:")
            print("-" * 50)
            for func_name, complexity in function_complexities.items():
                level = self._evaluate_complexity(complexity)
                recursive_marker = "🔄" if func_name in recursive_funcs else "📋"
                print(f"   {recursive_marker} {func_name}: {complexity} ({level})")
                
        print("="*70 + "\n")
        
    def _evaluate_complexity(self, complexity: int) -> str:
        """Karmaşıklık seviyesini değerlendir"""
        if complexity <= 5:
            return "🟢 Düşük (Basit)"
        elif complexity <= 10:
            return "🟡 Orta (Makul)"
        elif complexity <= 20:
            return "🟠 Yüksek (Karmaşık)"
        else:
            return "🔴 Çok Yüksek (Çok Karmaşık)"
            
    def _evaluate_big_o(self, big_o: str) -> str:
        """Big-O performansını değerlendir"""
        performance_map = {
            "O(1)": "🟢 Mükemmel (Sabit Zaman)",
            "O(log n)": "🟢 Çok İyi (Logaritmik)",
            "O(log² n)": "🟢 Çok İyi (Log Karesel)",
            "O(log³ n)": "🟢 İyi (Log Kübik)",
            "O(n)": "🟡 İyi (Doğrusal)",
            "O(n log n)": "🟡 Makul (Linearithmic)",
            "O(n²)": "🟠 Kötü (Karesel)",
            "O(n³)": "🔴 Çok Kötü (Kübik)",
            "O(2^n)": "🔴 Berbat (Üstel)",
            "O(n^k * 2^n)": "🔴 Felaket (Hibrit Üstel)"
        }
        return performance_map.get(big_o, "❓ Bilinmeyen")


def interactive_mode():
    """Sürekli çalışan interaktif mod"""
    analyzer = CodeComplexityAnalyzer()
    
    print("🚀 KOD KARMAŞIKLIĞI & BIG-O ANALİZ ARACI")
    print("="*60)
    print("💡 Kullanım:")
    print("   • Python kodunuzu yazın")
    print("   • Kod girişini bitirmek için boş satırda 'ANALIZ' yazın")
    print("   • Çıkmak için 'CIKIS' yazın")
    print("="*60)
    
    while True:
        print("\n📝 Lütfen Python kodunuzu girin:")
        print("   (Bitirmek için boş satırda 'ANALIZ' yazın)")
        print("-" * 40)
        
        code_lines = []
        while True:
            try:
                line = input()
                if line.strip().upper() == "ANALIZ":
                    break
                elif line.strip().upper() == "CIKIS":
                    print("\n Görüşürüz!")
                    return
                code_lines.append(line)
            except KeyboardInterrupt:
                print("\n\n Programa son verildi!")
                return
            except EOFError:
                print("\n\n Programa son verildi!")
                return
        
        code = '\n'.join(code_lines)
        
        if code.strip():
            print("\n🔍 Kod analiz ediliyor...")
            metrics = analyzer.analyze_code(code)
            analyzer.print_detailed_report(metrics)
            
            # Devam etmek istiyor mu?
            print("🔄 Yeni kod analizi yapmak ister misiniz? (E/H): ", end="")
            try:
                continue_choice = input().strip().upper()
                if continue_choice in ['H', 'N', 'NO', 'HAYIR']:
                    print("\n Görüşürüz!")
                    break
            except (KeyboardInterrupt, EOFError):
                print("\n\n Programa son verildi!")
                break
        else:
            print("⚠️  Boş kod girdiniz. Tekrar deneyin.")


def main():
    """Ana fonksiyon - komut satırından kullanım için"""
    if len(sys.argv) == 1:
        # Eğer hiç parametre verilmemişse, interaktif modu başlat
        interactive_mode()
        return
    
    if len(sys.argv) < 2:
        print("📖 Kullanım:")
        print("   python astparser.py                    # İnteraktif mod")
        print("   python astparser.py <dosya_yolu>       # Dosya analizi")
        print("   python astparser.py --interactive      # İnteraktif mod")
        return
        
    analyzer = CodeComplexityAnalyzer()
    
    if sys.argv[1] == "--interactive":
        interactive_mode()
    else:
        # Dosya analiz modu
        filepath = sys.argv[1]
        print(f"📁 Dosya analiz ediliyor: {filepath}")
        metrics = analyzer.analyze_file(filepath)
        analyzer.print_detailed_report(metrics)


if __name__ == "__main__":
    main()
