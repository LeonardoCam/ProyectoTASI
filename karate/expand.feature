# Pruebas de API (Gherkin/Karate). Requiere el backend en http://127.0.0.1:8000
# Ejecutar: java -jar karate.jar karate/expand.feature   (no ejecutado en el entorno de desarrollo)
Feature: Expansión de URLs y controles de seguridad

  Background:
    * url 'http://127.0.0.1:8000/api/v1'

  Scenario Outline: Bloqueo SSRF hacia destinos internos
    Given path 'expand'
    And request { url: '<destino>' }
    When method post
    Then status 400
    And match response.detail.code == '#string'

    Examples:
      | destino                                    |
      | http://127.0.0.1/                          |
      | http://localhost/                          |
      | http://169.254.169.254/latest/meta-data/   |
      | http://2130706433/                         |
      | http://0177.0.0.1/                         |
      | http://[::1]/                              |
      | file:///etc/passwd                         |

  Scenario: Resultado Medio o Alto incluye factores explicativos
    Given path 'expand'
    And request { url: 'http://github.com' }
    When method post
    Then status 200
    And match response.risk_score == '#number'
    And match response.risk_level == '#regex BAJO|MEDIO|ALTO'
    And match response.factors == '#array'

  Scenario: La segunda consulta se atiende desde la memoria inteligente
    Given path 'expand'
    And request { url: 'https://github.com' }
    When method post
    Then status 200
    Given path 'expand'
    And request { url: 'https://github.com' }
    When method post
    Then status 200
    And match response.cached == true
