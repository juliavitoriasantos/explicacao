using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using static System.Console;

namespace explicacao
{
    internal class Program
    {
        static void Main(string[] args)
        {
            WindowsIdentity identity = ExibeInfoIdentity();
            WindowsPrincipal principal = ExibeInfoPrincipal(identity);
            ExibeInfoClaims(principal.Claims);
            ReadLine();
        }
        public static WindowsIdentity ExibeInfoIdentity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity == null)
            {
                WriteLine("Não é um Windows Identity");
                return null;
            }
            WriteLine($"Tipo de Identity : {identity}");
            WriteLine("Imprime o nome completo do tipo de objeto (classe), útil para debug, para saber com que tipo de identidade você está lidando no seu código.\n");
            WriteLine("WindowsIdentity é uma classe no .NET que representa a identidade do usuário do Windows atualmente autenticado no sistema. Ela contém informações sobre o usuário que está rodando o processo.\n");
            WriteLine($"Nome : {identity.Name}");
            WriteLine("Acessa a propriedde Name do objeto Identity, imprime o nome do usuário atual. Possui o nome do computador/domínio.\n");
            WriteLine($"Autenticado : {identity.IsAuthenticated}");
            WriteLine("Verifica se a identidade foi autenticada pelo sistema, imprime True, caso for verdadeiro pode confiar que a identidade do usuário é legítima, ou False, caso for falso deve tratar o usuário como não autenticado, podendo negar acesso a recursos protegidos ou exigir login.\n");
            WriteLine($"Tipo de Autenticação : {identity.AuthenticationType}");
            WriteLine("Acessa a propriedade AuthenticationType, que indica o método usado para autenticação do usuário.\n");
            WriteLine("Kerberos é um protocolo de autenticação de rede projetado para fornecer autenticação segura usando tickets e criptografia. Ele foi desenvolvido no MIT e é amplamente usado em redes corporativas, especialmente em ambientes Microsoft Windows com Active Directory.\n");
            WriteLine($"É usuário Anônimo ? : {identity.IsAnonymous}");
            WriteLine("Verifica se o usuário é anônimo, imprime True caso for verdadeiro ou False, caso for falso não está autenticado e não possui uma identidade reconhecida pelo sistema.\n");
            WriteLine($"Token de acesso : " + $"{identity.AccessToken.DangerousGetHandle()}");
            WriteLine("Mostra o handle (ponteiro), que é um identificador que o sistema operacional usa internamente para acessar recursos do token de segurança. Esse token é uma estrutura usada pelo Windows para descrever os privilégios e a identidade do processo ou thread.\n");
            WriteLine();
            return identity;
        }
        public static WindowsPrincipal ExibeInfoPrincipal(WindowsIdentity identity)
        {
            WriteLine("Informação do Principal");
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            WriteLine("Imprime Informação do principal.\n");
           if (principal == null)
            {
                WriteLine("Não é um Windows Principal");
                return null;
            }
            WriteLine($"É Usuário ? {principal.IsInRole(WindowsBuiltInRole.User)}");
            WriteLine("Verifica se o usuário pertence ao grupo User.\n");
            WriteLine($"É Administrador ? {principal.IsInRole(WindowsBuiltInRole.Administrator)}");
            WriteLine("Verifica se o usuário é administrador. Caso True, significa que o usuário possui permissões especiais no sistema, enquanto o False significa que tem acesso limitado.\n");
            WriteLine();
            return principal;
        }
        public static void ExibeInfoClaims(IEnumerable<Claim> claims)
        {
            WriteLine("Declarações (Claims) ");
            WriteLine("Imprime Declarações (Clains).\n");

           

            foreach (var claim in claims)
            {
                WriteLine($"Assunto : {claim.Subject}");
                WriteLine("Acessa a propriedade Subject do claim. claim.Subject é a identidade associada à declaração.\n");
                WriteLine($"Emissor : {claim.Issuer}");
                WriteLine($"Mostra o emissor (issuer) da claim. claim.Issuer mostra quem garantiu que a informação é verdadeira.\n");
                WriteLine($"Tipo : {claim.Type}");
                WriteLine($"Mostra o tipo da claim, ou seja, o que ela representa. claim.Type diz qual informação está sendo fornecida sobre o usuário.\n"); 
                WriteLine($"Valor do Tipo : {claim.ValueType}");
                WriteLine($"Mostra o tipo de dado do valor contido na claim.\n");
                WriteLine($"Valor : {claim.Value}");
                WriteLine($"Mostra o valor real da claim.\n");
                foreach (var prop in claim.Properties)
                {
                    WriteLine($"\tProperty: {prop.Key} {prop.Value}");
                    if (prop.Key == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowssubauthority")
                    {
                        string authority = prop.Value;

                        if (authority.Equals("NTAuthority", StringComparison.OrdinalIgnoreCase))
                        {
                            WriteLine("\t==> NT Authority: Representa contas e serviços internos do Windows como SYSTEM, LOCAL SERVICE e NETWORK SERVICE.");
                            WriteLine("\t    Usado para executar processos e serviços com permissões específicas do sistema.\n");
                        }
                        else if (authority.Equals("LocalAuthority", StringComparison.OrdinalIgnoreCase) ||
                authority.Equals("LOCAL", StringComparison.OrdinalIgnoreCase) ||
                authority.Equals("LocalService", StringComparison.OrdinalIgnoreCase))
                        {
                            WriteLine("\t==> Local Authority: Representa contas de serviço locais com permissões limitadas.");
                            WriteLine("\t    Usado para serviços que precisam rodar localmente sem privilégios elevados.\n");
                        }
                        else if (authority.Equals("WorldAuthority", StringComparison.OrdinalIgnoreCase) ||
                                 authority.Equals("World", StringComparison.OrdinalIgnoreCase) ||
                                 authority.Equals("Everyone", StringComparison.OrdinalIgnoreCase))
                        {
                            WriteLine("\t==> World Authority: Representa todos os usuários, autenticados ou não.");
                            WriteLine("\t    Usado para conceder permissões públicas ou gerais a todos os usuários do sistema.\n");
                        }
                        else
                        {
                            WriteLine("\t==> Autoridade desconhecida.");
                            WriteLine("\t    Essa autoridade não é reconhecida entre as comuns do Windows.\n");
                        }
                    }
                }

                WriteLine();
            }
        }
    }
}
