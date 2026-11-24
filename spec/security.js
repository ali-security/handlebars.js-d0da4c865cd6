describe('security issues', function() {
    describe('GH-1495: Prevent Remote Code Execution via constructor', function() {
        it('should not allow constructors to be accessed', function() {
            expectTemplate('{{lookup (lookup this "constructor") "name"}}')
                .withInput({})
                .toCompileTo('');

            expectTemplate('{{constructor.name}}')
                .withInput({})
                .toCompileTo('');
        });

        it('GH-1603: should not allow constructors to be accessed (lookup via toString)', function() {
          expectTemplate('{{lookup (lookup this (list "constructor")) "name"}}')
              .withInput({})
              .withHelper('list', function(element) {
                return [element];
              })
              .toCompileTo('');
        });


      it('should allow the "constructor" property to be accessed if it is an "ownProperty"', function() {
            shouldCompileTo('{{constructor.name}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {'constructor': {
                'name': 'here we go'
            }}, 'here we go');
        });

        it('should allow the "constructor" property to be accessed if it is an "own property"', function() {
            shouldCompileTo('{{lookup (lookup this "constructor") "name"}}', {'constructor': {
                    'name': 'here we go'
                }}, 'here we go');
        });
    });

    describe('GH-1558: Prevent explicit call of helperMissing-helpers', function() {
        if (!Handlebars.compile) {
            return;
        }

        describe('without the option "allowExplicitCallOfHelperMissing"', function() {
            it('should throw an exception when calling  "{{helperMissing}}" ', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{helperMissing}}');
                    template({});
                }, Error);
            });
            it('should throw an exception when calling  "{{#helperMissing}}{{/helperMissing}}" ', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{#helperMissing}}{{/helperMissing}}');
                    template({});
                }, Error);
            });
            it('should throw an exception when calling  "{{blockHelperMissing "abc" .}}" ', function() {
                var functionCalls = [];
                expect(function() {
                    var template = Handlebars.compile('{{blockHelperMissing "abc" .}}');
                    template({ fn: function() { functionCalls.push('called'); }});
                }).to.throw(Error);
                expect(functionCalls.length).to.equal(0);
            });
            it('should throw an exception when calling  "{{#blockHelperMissing .}}{{/blockHelperMissing}}"', function() {
                shouldThrow(function() {
                    var template = Handlebars.compile('{{#blockHelperMissing .}}{{/blockHelperMissing}}');
                    template({ fn: function() { return 'functionInData';}});
                }, Error);
            });
        });

        describe('with the option "allowCallsToHelperMissing" set to true', function() {
            it('should not throw an exception when calling  "{{helperMissing}}" ', function() {
                    var template = Handlebars.compile('{{helperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
            it('should not throw an exception when calling  "{{#helperMissing}}{{/helperMissing}}" ', function() {
                    var template = Handlebars.compile('{{#helperMissing}}{{/helperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
            it('should not throw an exception when calling  "{{blockHelperMissing "abc" .}}" ', function() {
                    var functionCalls = [];
                    var template = Handlebars.compile('{{blockHelperMissing "abc" .}}');
                    template({ fn: function() { functionCalls.push('called'); }}, {allowCallsToHelperMissing: true});
                    equals(functionCalls.length, 1);
            });
            it('should not throw an exception when calling  "{{#blockHelperMissing .}}{{/blockHelperMissing}}"', function() {
                    var template = Handlebars.compile('{{#blockHelperMissing true}}sdads{{/blockHelperMissing}}');
                    template({}, {allowCallsToHelperMissing: true});
            });
        });
    });

    describe('GH-1563', function() {
        it('should not allow to access constructor after overriding via __defineGetter__', function() {
            if (({}).__defineGetter__ == null || ({}).__lookupGetter__ == null) {
                return this.skip(); // Browser does not support this exploit anyway
            }
            expectTemplate('{{__defineGetter__ "undefined" valueOf }}' +
                '{{#with __lookupGetter__ }}' +
                '{{__defineGetter__ "propertyIsEnumerable" (this.bind (this.bind 1)) }}' +
                '{{constructor.name}}' +
                '{{/with}}')
                .withInput({})
                .toThrow(/Missing helper: "__defineGetter__"/);
        });
    });

    describe('GH-1595', function() {
      it('properties, that are required to be own properties', function() {
        expectTemplate('{{constructor}}').withInput({}).toCompileTo('');
        expectTemplate('{{__defineGetter__}}').withInput({}).toCompileTo('');
        expectTemplate('{{__defineSetter__}}').withInput({}).toCompileTo('');
        expectTemplate('{{__lookupGetter__}}').withInput({}).toCompileTo('');
        expectTemplate('{{__lookupSetter__}}').withInput({}).toCompileTo('');
        expectTemplate('{{__proto__}}').withInput({}).toCompileTo('');

        expectTemplate('{{lookup this "constructor"}}').withInput({}).toCompileTo('');
        expectTemplate('{{lookup this "__defineGetter__"}}').withInput({}).toCompileTo('');
        expectTemplate('{{lookup this "__defineSetter__"}}').withInput({}).toCompileTo('');
        expectTemplate('{{lookup this "__lookupGetter__"}}').withInput({}).toCompileTo('');
        expectTemplate('{{lookup this "__lookupSetter__"}}').withInput({}).toCompileTo('');
        expectTemplate('{{lookup this "__proto__"}}').withInput({}).toCompileTo('');
      });

      it('GHSA-7rx3-28cr-v5wh: should not allow __lookupSetter__ to be called on the context', function() {
        if (({}).__lookupSetter__ == null) {
          return this.skip(); // Browser does not support this exploit anyway
        }
        expectTemplate('{{__lookupSetter__ "__proto__"}}')
            .withInput({})
            .toThrow(/Missing helper: "__lookupSetter__"/);
        expectTemplate('{{lookup this "__lookupSetter__"}}').withInput({}).toCompileTo('');
      });

      describe('GH-1631: disallow access to prototype functions', function() {
        function TestClass() {}

        TestClass.prototype.aProperty = 'propertyValue';
        TestClass.prototype.aMethod = function() {
          return 'returnValue';
        };

        describe('control access to prototype methods via "allowedProtoMethods"', function() {
          it('should be prohibited by default', function() {
            expectTemplate('{{aMethod}}')
                .withInput(new TestClass())
                .toCompileTo('');
          });

          it('can be allowed', function() {
            expectTemplate('{{aMethod}}')
                .withInput(new TestClass())
                .withRuntimeOptions({
                  allowedProtoMethods: {
                    aMethod: true
                  }
                })
                .toCompileTo('returnValue');
          });

          it('should be prohibited by default (in "compat" mode)', function() {
            expectTemplate('{{aMethod}}')
                .withInput(new TestClass())
                .withCompileOptions({ compat: true })
                .toCompileTo('');
          });

          it('can be allowed (in "compat" mode)', function() {
            expectTemplate('{{aMethod}}')
                .withInput(new TestClass())
                .withCompileOptions({ compat: true })
                .withRuntimeOptions({
                  allowedProtoMethods: {
                    aMethod: true
                  }
                })
                .toCompileTo('returnValue');
          });

          it('should cause the recursive lookup by default (in "compat" mode)', function() {
            expectTemplate('{{#aString}}{{trim}}{{/aString}}')
                .withInput({ aString: '  abc  ', trim: 'trim' })
                .withCompileOptions({ compat: true })
                .toCompileTo('trim');
          });

          it('should not cause the recursive lookup if allowed through options(in "compat" mode)', function() {
            expectTemplate('{{#aString}}{{trim}}{{/aString}}')
                .withInput({ aString: '  abc  ', trim: 'trim' })
                .withCompileOptions({ compat: true })
                .withRuntimeOptions({
                  allowedProtoMethods: {
                    trim: true
                  }
                })
                .toCompileTo('abc');
          });
        });

        describe('control access to prototype non-methods via "allowedProtoProperties"', function() {
          it('should be prohibited by default', function() {
            expectTemplate('{{aProperty}}')
                .withInput(new TestClass())
                .toCompileTo('');
          });

          it('can be turned on', function() {
            expectTemplate('{{aProperty}}')
                .withInput(new TestClass())
                .withRuntimeOptions({
                  allowedProtoProperties: {
                    aProperty: true
                  }
                })
                .toCompileTo('propertyValue');
          });

          it('should be prohibited by default (in "compat" mode)', function() {
            expectTemplate('{{aProperty}}')
                .withInput(new TestClass())
                .withCompileOptions({ compat: true })
                .toCompileTo('');
          });

          it('can be turned on (in "compat" mode)', function() {
            expectTemplate('{{aProperty}}')
                .withInput(new TestClass())
                .withCompileOptions({ compat: true })
                .withRuntimeOptions({
                  allowedProtoProperties: {
                    aProperty: true
                  }
                })
                .toCompileTo('propertyValue');
          });
        });

        describe('memory exhaustion by calling prototype methods from templates', function() {
          // Calling e.g. String.prototype.repeat with a large count from a template
          // allows to crash the server by consuming a lot of memory.
          it('should not call prototype methods as helpers', function() {
            expectTemplate('{{#with "abc"}}{{repeat 3}}{{/with}}')
                .toThrow(/Missing helper: "repeat"/);
          });

          it('should not call prototype methods as helpers (in "compat" mode)', function() {
            expectTemplate('{{#with "abc"}}{{repeat 3}}{{/with}}')
                .withCompileOptions({ compat: true })
                .toThrow(/Missing helper: "repeat"/);
          });

          it('should not call prototype methods as block helpers', function() {
            expectTemplate('{{#with "abc"}}{{#repeat 3}}{{/repeat}}{{/with}}')
                .toThrow(/Missing helper: "repeat"/);
          });

          it('should not call prototype methods in subexpressions', function() {
            expectTemplate('{{#with "abc"}}{{lookup (repeat 3) "length"}}{{/with}}')
                .toThrow(/Missing helper: "repeat"/);
          });

          it('should not call prototype methods via a path', function() {
            expectTemplate('{{#with this as |obj|}}{{obj.aString.repeat 3}}{{/with}}')
                .withInput({ aString: 'abc' })
                .toThrow(/Missing helper: "obj.aString.repeat"/);
          });

          it('should not call prototype methods without parameters', function() {
            expectTemplate('{{#with "  abc  "}}{{trim}}{{/with}}')
                .toCompileTo('');
          });

          it('should not return prototype methods from the "lookup"-helper', function() {
            expectTemplate('{{#with "abc"}}{{lookup this "repeat"}}{{/with}}')
                .toCompileTo('');
          });

          it('should still call prototype methods that are allowed via "allowedProtoMethods"', function() {
            expectTemplate('{{#with "abc"}}{{repeat 3}}{{/with}}')
                .withRuntimeOptions({
                  allowedProtoMethods: {
                    repeat: true
                  }
                })
                .toCompileTo('abcabcabc');
          });
        });

        describe('in partials', function() {
          it('should be prohibited by default', function() {
            expectTemplate('{{> aPartial}}')
                .withInput(new TestClass())
                .withPartial('aPartial', '{{aMethod}} {{aProperty}}')
                .toCompileTo(' ');
          });

          it('should pass "allowedProtoMethods" and "allowedProtoProperties" to partials', function() {
            expectTemplate('{{> aPartial}}')
                .withInput(new TestClass())
                .withPartial('aPartial', '{{aMethod}} {{aProperty}}')
                .withRuntimeOptions({
                  allowedProtoMethods: {
                    aMethod: true
                  },
                  allowedProtoProperties: {
                    aProperty: true
                  }
                })
                .toCompileTo('returnValue propertyValue');
          });
        });

        describe('compatibility with old runtimes, that do not provide the function "container.lookupProperty"', function() {
          beforeEach(function simulateRuntimeWithoutLookupProperty() {
            var oldTemplateMethod = handlebarsEnv.template;
            sinon.replace(handlebarsEnv, 'template', function(templateSpec) {
              templateSpec.main = wrapToAdjustContainer(templateSpec.main);
              return oldTemplateMethod.call(this, templateSpec);
            });
          });

          afterEach(function() {
            sinon.restore();
          });

          it('should work with simple properties', function() {
            expectTemplate('{{aProperty}}')
                .withInput({ aProperty: 'propertyValue' })
                .toCompileTo('propertyValue');
          });

          it('should work with Array.prototype.length', function() {
            expectTemplate('{{anArray.length}}')
                .withInput({ anArray: ['a', 'b', 'c'] })
                .toCompileTo('3');
          });
        });
      });
    });

    describe('GH-1736: dangerous properties in strict, compat and assumeObjects mode', function() {
      checkDangerousPropertyAccess('in strict mode', { strict: true });
      checkDangerousPropertyAccess('in compat mode', { compat: true });
      checkDangerousPropertyAccess('in assumeObjects mode', { assumeObjects: true });

      function checkDangerousPropertyAccess(title, compileOptions) {
        describe(title, function() {
          it('should not allow dangerous properties to be accessed', function() {
            expectTemplate('{{constructor}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{__defineGetter__}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{__defineSetter__}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{__lookupGetter__}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{__lookupSetter__}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{__proto__}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
            expectTemplate('{{@root.constructor}}').withCompileOptions(compileOptions).withInput({}).toCompileTo('');
          });

          it('should allow the "constructor" property to be accessed if it is enumerable', function() {
            expectTemplate('{{constructor}}')
                .withCompileOptions(compileOptions)
                .withInput({'constructor': 'here we go'})
                .toCompileTo('here we go');
            expectTemplate('{{constructor.name}}')
                .withCompileOptions(compileOptions)
                .withInput({'constructor': {'name': 'here we go'}})
                .toCompileTo('here we go');
          });

          it('should not allow __defineGetter__ to be called on the context', function() {
            var input = {};
            expect(function() {
              CompilerContext.compile('{{__defineGetter__ "injected" valueOf}}', compileOptions)(input);
            }).to.throw(Error);
            expect(Object.prototype.hasOwnProperty.call(input, 'injected')).to.equal(false);
          });

          it('should not allow Object.prototype to be polluted via __proto__', function() {
            try {
              expectTemplate('{{#__proto__}}{{__defineGetter__ "pollutedByHandlebars" valueOf}}{{/__proto__}}')
                  .withCompileOptions(compileOptions)
                  .withInput({})
                  .toCompileTo('');
              expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'pollutedByHandlebars')).to.equal(false);
            } finally {
              delete Object.prototype.pollutedByHandlebars;
            }
          });
        });
      }
    });

    describe('GH-1736: escapes template variables', function() {
      it('in compat mode', function() {
        expectTemplate("{{'a\\b'}}")
          .withCompileOptions({ compat: true })
          .withInput({ 'a\\b': 'c' })
          .toCompileTo('c');
      });

      it('in default mode', function() {
        expectTemplate("{{'a\\b'}}")
          .withCompileOptions()
          .withInput({ 'a\\b': 'c' })
          .toCompileTo('c');
      });
      it('in default mode', function() {
        expectTemplate("{{'a\\b'}}")
          .withCompileOptions({ strict: true })
          .withInput({ 'a\\b': 'c' })
          .toCompileTo('c');
      });

      it('should not allow code injection via the property name in compat mode', function() {
        expectTemplate('{{\'") + "INJECTED" + ("\'}}')
          .withCompileOptions({ compat: true })
          .withInput({})
          .toCompileTo('');
      });
    });

    describe('GHSA-2qvq-rjwj-gvw9: partial resolution must not use polluted prototypes', function() {
      afterEach(function() {
        delete Object.prototype.widget;
      });

      it('should not resolve partial names from Object.prototype', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype.widget = '<img src=x onerror="alert(1)">';

        expect(function() {
          CompilerContext.compileWithPartial('<div>{{> widget}}</div>')({});
        }).to.throw(/could not be found/);
      });

      it('should not invoke partial functions inherited from Object.prototype', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype.widget = function() {
          return '<img src=x onerror="alert(1)">';
        };

        expect(function() {
          CompilerContext.compile('<div>{{> widget}}</div>')({});
        }).to.throw(/could not be found/);
      });

      it('should still render registered partials', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype.widget = '<img src=x onerror="alert(1)">';

        expectTemplate('<div>{{> widget}}</div>')
          .withPartial('widget', 'safe')
          .toCompileTo('<div>safe</div>');
      });
    });

    describe('GHSA-2w6w-674q-4c4q, GHSA-xhpv-hc6g-r9c6, GHSA-3mfm-83xf-c92r, GHSA-8r5x-fm3f-whwj: untrusted AST inputs', function() {
      if (!Handlebars.compile) {
        return;
      }

      function createInjectedProgram() {
        var loc = {
          source: null,
          start: { line: 1, column: 0 },
          end: { line: 1, column: 20 }
        };
        return {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: {
                open: false,
                close: false
              },
              loc: loc,
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['lookup'],
                original: 'lookup',
                loc: loc
              },
              params: [
                {
                  type: 'PathExpression',
                  data: false,
                  depth: 0,
                  parts: [],
                  original: 'this',
                  loc: loc
                },
                {
                  type: 'NumberLiteral',
                  value: '{},{})) + (Function) + (({}',
                  original: 1,
                  loc: loc
                }
              ]
            }
          ]
        };
      }

      it('should reject AST NumberLiteral type confusion in compile()', function() {
        // NumberLiteral.value is emitted as a raw JavaScript literal, so the
        // compiler rejects anything that is not a number.
        expect(function() {
          var template = Handlebars.compile(createInjectedProgram());
          template({});
        }).to.throw(/Invalid AST: NumberLiteral value must be a number/);
      });

      it('should reject AST NumberLiteral type confusion in precompile()', function() {
        expect(function() {
          Handlebars.precompile(createInjectedProgram());
        }).to.throw(/Invalid AST: NumberLiteral value must be a number/);
      });

      it('should reject AST objects passed via dynamic partial lookup', function() {
        expect(function() {
          var template = Handlebars.compile('{{> (lookup . "payload")}}');
          template({
            payload: createInjectedProgram()
          });
        }).to.throw(/could not be found/);
      });

      it('should not compile data objects passed via dynamic partial lookup', function() {
        // resolvePartial() used to accept any value with a truthy "call"
        // property as a compiled partial. A JSON object with "call" and
        // "type": "Program" then reached env.compile() and was rendered as a
        // template. Such values are now treated as partial names instead.
        var payload = createInjectedProgram();
        payload.call = 1;
        payload.body[0].escaped = false;

        expect(function() {
          var template = Handlebars.compile('{{> (lookup . "payload")}}');
          template({ payload: payload });
        }).to.throw(/could not be found/);
      });

      it('should not compile AST-shaped objects registered as partials', function() {
        expect(function() {
          var template = Handlebars.compile('{{> payload}}');
          template({}, { partials: { payload: createInjectedProgram() } });
        }).to.throw(/must be strings or functions/);
      });

      it('should not compile an AST injected into @partial-block', function() {
        // A helper that writes arbitrary values into the data frame can
        // replace @partial-block with a crafted AST. It must never be compiled.
        var payload = {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: false,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['injected'],
                original: 'injected'
              },
              params: []
            }
          ]
        };
        var template = Handlebars.compile('{{#> wrapper}}block{{/wrapper}}');

        expect(function() {
          template({ injected: '<script>alert(1)</script>' }, {
            helpers: {
              tamper: function(options) {
                options.data['partial-block'] = payload;
              }
            },
            partials: {
              wrapper: '{{tamper}}{{> @partial-block}}'
            }
          });
        }).to.throw(/must be strings or functions/);
      });

      it('should reject a non-integer param depth in stringParams mode', function() {
        // pushParam passes val.depth to the getContext opcode. In stringParams
        // mode, getContext stores the depth in lastContext, which contextName
        // interpolates into generated code as 'depths[' + depth + ']'. A depth
        // that is not a non-negative integer is therefore rejected.
        var loc = {
          source: null,
          start: { line: 1, column: 0 },
          end: { line: 1, column: 20 }
        };
        var maliciousAST = {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              loc: loc,
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['lookup'],
                original: 'lookup',
                loc: loc
              },
              params: [
                {
                  type: 'PathExpression',
                  data: false,
                  depth: 'function(){throw new Error("INJECTION")}()',
                  parts: [],
                  original: '',
                  loc: loc
                }
              ]
            }
          ]
        };

        expect(function() {
          var template = Handlebars.compile(maliciousAST, {
            stringParams: true
          });
          template({});
        }).to.throw(
          /Invalid AST: PathExpression depth must be a non-negative integer/
        );
      });

      it('should reject a non-integer data path depth', function() {
        // lookupData interpolates the depth into generated code as
        // 'container.data(data, ' + depth + ')'.
        var maliciousAST = {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: true,
                depth: '1) + (function(){throw new Error("INJECTION")})() + (1',
                parts: ['root'],
                original: '@root'
              },
              params: []
            }
          ]
        };

        expect(function() {
          Handlebars.compile(maliciousAST)({});
        }).to.throw(
          /Invalid AST: PathExpression depth must be a non-negative integer/
        );
      });

      it('should reject non-array blockParams', function() {
        // The compiler reads program.blockParams.length from the AST and
        // javascript-compiler.js interpolates that value verbatim into a
        // container.program(...) call. blockParams must therefore be an array
        // of strings, so that the length is always a safe integer.
        var maliciousAST = {
          type: 'Program',
          loc: { start: { line: 1, column: 0 } },
          body: [
            {
              type: 'BlockStatement',
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['rce'],
                original: 'rce',
                loc: { start: { line: 1, column: 0 } }
              },
              params: [],
              program: {
                type: 'Program',
                blockParams: {
                  length: "(()=>{throw new Error('INJECTION')})()"
                },
                body: [],
                loc: { start: { line: 1, column: 0 } }
              },
              openStrip: { open: false, close: false },
              inverseStrip: { open: false, close: false },
              closeStrip: { open: false, close: false },
              loc: { start: { line: 1, column: 0 } }
            }
          ]
        };

        expect(function() {
          var template = Handlebars.compile(maliciousAST, {
            stringParams: true
          });
          template({});
        }).to.throw(/Invalid AST: Program blockParams must be an array/);
      });

      it('should reject non-number NumberLiteral values in stringParams mode', function() {
        // In stringParams mode, pushStringParam emits any non-string param
        // value as a raw literal, and the code generator concatenates array
        // chunks verbatim. The NumberLiteral handler therefore rejects any
        // value that is not a number.
        var loc = {
          source: null,
          start: { line: 1, column: 0 },
          end: { line: 1, column: 20 }
        };
        var maliciousAST = {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              loc: loc,
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['helper'],
                original: 'helper',
                loc: loc
              },
              params: [
                {
                  type: 'NumberLiteral',
                  value: ['(function(){throw new Error("INJECTION")})()'],
                  original: 1,
                  loc: loc
                }
              ]
            }
          ]
        };

        expect(function() {
          var template = Handlebars.compile(maliciousAST, {
            stringParams: true
          });
          template({});
        }).to.throw(/Invalid AST: NumberLiteral value must be a number/);
      });

      it('should stringify non-string PathExpression originals in stringParams mode', function() {
        // pushStringParam emits non-string values as raw literals, so the
        // `original` of a path param must never reach it as anything else.
        var maliciousAST = {
          type: 'Program',
          body: [
            {
              type: 'MustacheStatement',
              escaped: true,
              strip: { open: false, close: false },
              path: {
                type: 'PathExpression',
                data: false,
                depth: 0,
                parts: ['helper'],
                original: 'helper'
              },
              params: [
                {
                  type: 'PathExpression',
                  data: false,
                  depth: 0,
                  parts: ['foo'],
                  original: ['(function(){throw new Error("INJECTION")})()']
                }
              ]
            }
          ]
        };

        var template = Handlebars.compile(maliciousAST, { stringParams: true });
        expect(template({}, {
          helpers: {
            helper: function(value) {
              return typeof value;
            }
          }
        })).to.equal('string');
      });

      it('should only dispatch known AST node types', function() {
        // Compiler#accept() dispatches on node.type. Without an allowlist, a
        // crafted type would call an arbitrary Compiler method with the node as
        // its argument. Params are used because WhitespaceControl does not
        // visit them, so they reach the compiler unchecked.
        var loc = {
          source: null,
          start: { line: 1, column: 0 },
          end: { line: 1, column: 20 }
        };
        [
          'compile',
          'opcode',
          'pushParam',
          'constructor',
          'hasOwnProperty',
          '__proto__'
        ].forEach(function(type) {
          var template = Handlebars.compile({
            type: 'Program',
            body: [
              {
                type: 'MustacheStatement',
                escaped: true,
                strip: { open: false, close: false },
                loc: loc,
                path: {
                  type: 'PathExpression',
                  data: false,
                  depth: 0,
                  parts: ['helper'],
                  original: 'helper',
                  loc: loc
                },
                params: [{ type: type, loc: loc }]
              }
            ]
          });
          expect(function() {
            template({});
          }).to.throw(/Unknown type: /);
        });
      });
    });

    describe('GHSA-442j-39wm-28r2: lookup must return checked value', function() {
      it('should use the validated value from lookupProperty() in compat mode', function() {
        var input = { child: {} };
        var readCount = 0;
        Object.defineProperty(input, 'unstable', {
          enumerable: true,
          get: function() {
            readCount++;
            return readCount === 1 ? 'first-read' : 'second-read';
          }
        });

        expectTemplate('{{#with child}}{{unstable}}{{/with}}')
          .withInput(input)
          .withCompileOptions({ compat: true })
          .toCompileTo('first-read');
      });
    });

    describe('GHSA-9cx6-37pm-9jff: malformed decorators should fail safely', function() {
      it('should throw a controlled error for unknown decorators', function() {
        expect(function() {
          CompilerContext.compile('{{*notRegistered}}')({});
        }).to.throw(/Missing decorator: "notRegistered"/);
      });

      it('should throw a controlled error for unknown block decorators', function() {
        expect(function() {
          CompilerContext.compile('{{#*notRegistered}}content{{/notRegistered}}')({});
        }).to.throw(/Missing decorator: "notRegistered"/);
      });

      it('should still run registered decorators', function() {
        expectTemplate('{{#*inline "myPartial"}}success{{/inline}}{{> myPartial}}')
          .toCompileTo('success');
      });
    });

    describe('GHSA-xw65-4hp5-5hc7: precompiled output must be safe in script tags', function() {
      var name = '</script><script>alert(1)</script>';

      function expectSafePrecompile(template, options) {
        if (Handlebars.precompile) {
          var precompiled = Handlebars.precompile(template, options);

          expect(precompiled).to.not.match(/<(!--|\/?script)/i);
          return precompiled;
        }
      }

      it('should escape script tag delimiters in static content', function() {
        var template = 'safe</ScRiPt ><span>alert(1)</script><SCRIPT>';
        var precompiled = expectSafePrecompile(template);
        if (precompiled) {
          expect(precompiled).to.contain('\\u003C/ScRiPt >');
          expect(precompiled).to.contain('\\u003CSCRIPT>');
        }
        expectTemplate(template).toCompileTo(template);
      });

      it('should escape HTML comment openers in static content', function() {
        var template = '<!--<script>';
        var precompiled = expectSafePrecompile(template);
        if (precompiled) {
          expect(precompiled).to.contain('\\u003C!--\\u003Cscript>');
        }
        expectTemplate(template).toCompileTo(template);
      });

      it('should not escape other markup in static content', function() {
        var template = '<div class="a"><span>b</span></div><!- ->';
        var precompiled = expectSafePrecompile(template);
        if (precompiled) {
          expect(precompiled).to.contain(
            '<div class=\\"a\\"><span>b</span></div><!- ->'
          );
        }
        expectTemplate(template).toCompileTo(template);
      });

      it('should escape script tag delimiters in string literals', function() {
        expectSafePrecompile('{{echo "' + name + '" key="' + name + '"}}');
        expectTemplate('{{{echo "' + name + '" key="' + name + '"}}}')
          .withHelper('echo', function(value, options) {
            return value + options.hash.key;
          })
          .toCompileTo(name + name);
      });

      it('should escape script tag delimiters in property lookups', function() {
        var input = {};
        input[name] = 'success';
        expectSafePrecompile('{{[' + name + ']}}');
        expectTemplate('{{[' + name + ']}}')
          .withInput(input)
          .toCompileTo('success');
        expectSafePrecompile('{{foo.[' + name + ']}}');
        expectTemplate('{{foo.[' + name + ']}}')
          .withInput({ foo: input })
          .toCompileTo('success');
      });

      it('should escape script tag delimiters in data lookups', function() {
        var data = {};
        data[name] = 'success';
        expectSafePrecompile('{{@[' + name + ']}}');
        expectTemplate('{{@[' + name + ']}}')
          .withRuntimeOptions({ data: data })
          .toCompileTo('success');
      });

      it('should escape script tag delimiters in helper and partial names', function() {
        expectSafePrecompile('{{#[' + name + ']}}x{{/[' + name + ']}}');
        expectTemplate('{{#[' + name + ']}}x{{/[' + name + ']}}')
          .withHelper(name, function(options) {
            return options.fn(this);
          })
          .toCompileTo('x');
        expectSafePrecompile('{{> [' + name + ']}}');
        expectTemplate('{{> [' + name + ']}}')
          .withPartial(name, 'success')
          .toCompileTo('success');
      });

      it('should escape script tag delimiters in compat mode lookups', function() {
        var input = {};
        input[name] = 'success';
        expectSafePrecompile('{{[' + name + ']}}', { compat: true });
        expectTemplate('{{[' + name + ']}}')
          .withCompileOptions({ compat: true })
          .withInput(input)
          .toCompileTo('success');
      });

      it('should escape script tag delimiters in tracked block param ids', function() {
        var template =
          '{{#each items as |item|}}{{{id item.[' + name + ']}}}{{/each}}';
        var item = {};
        item[name] = 'value';
        expectSafePrecompile(template, { trackIds: true });
        expectTemplate(template)
          .withCompileOptions({ trackIds: true })
          .withHelper('id', function(value, options) {
            return options.ids[0];
          })
          .withInput({ items: [item] })
          .toCompileTo('items.0.' + name);
      });

      it('should escape script tag delimiters in source locations', function() {
        if (!Handlebars.precompile) {
          return;
        }
        // Source locations, which include the srcName option, are emitted as
        // JSON object literals for helper calls.
        var code = Handlebars.precompile('{{echo}}', { srcName: name }).code;
        expect(code).to.not.match(/<(!--|\/?script)/i);

        var loc = code.match(/"loc":(\{.*?\}\})/);
        expect(JSON.parse(loc[1]).source).to.equal(name);
      });

      it('should escape line separators in source locations', function() {
        if (!Handlebars.precompile) {
          return;
        }
        // U+2028 and U+2029 end string literals in ES5.
        var separators =
            String.fromCharCode(0x2028) + String.fromCharCode(0x2029),
          srcName = 'a' + separators + 'b';
        var code = Handlebars.precompile('{{echo}}', { srcName: srcName }).code;
        expect(code).to.not.contain(String.fromCharCode(0x2028));
        expect(code).to.not.contain(String.fromCharCode(0x2029));

        var loc = code.match(/"loc":(\{.*?\}\})/);
        expect(JSON.parse(loc[1]).source).to.equal(srcName);
      });
    });

    describe('GHSA-3mfm-83xf-c92r: @partial-block must not resolve from polluted prototype', function() {
      if (!Handlebars.compile) {
        return;
      }

      afterEach(function() {
        delete Object.prototype['partial-block'];
        delete Object.prototype['@partial-block'];
      });

      it('should not resolve @partial-block from Object.prototype', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype['partial-block'] = '<img src=x onerror="alert(1)">';

        expect(function() {
          Handlebars.compile('{{> @partial-block}}')({});
        }).to.throw(/could not be found/);
      });

      it('should not resolve @partial-block from Object.prototype inside a partial', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype['partial-block'] = '<img src=x onerror="alert(1)">';

        Handlebars.registerPartial('testPartial', '{{> @partial-block}}');
        try {
          expect(function() {
            Handlebars.compile('{{> testPartial}}')({});
          }).to.throw(/could not be found/);
        } finally {
          Handlebars.unregisterPartial('testPartial');
        }
      });

      it('should not resolve an inherited "@partial-block" partial', function() {
        // eslint-disable-next-line no-extend-native
        Object.prototype['@partial-block'] = '<img src=x onerror="alert(1)">';

        expect(function() {
          Handlebars.compile('{{> @partial-block}}')({});
        }).to.throw(/could not be found/);
      });

      it('should still render legitimate @partial-block content', function() {
        Handlebars.registerPartial('wrapper', '<div>{{> @partial-block}}</div>');
        try {
          var result = Handlebars.compile('{{#> wrapper}}hello{{/wrapper}}')({});
          expect(result).to.equal('<div>hello</div>');
        } finally {
          Handlebars.unregisterPartial('wrapper');
        }
      });
    });
});

function wrapToAdjustContainer(precompiledTemplateFunction) {
  return function templateFunctionWrapper(container /*, more args */) {
    delete container.lookupProperty;
    return precompiledTemplateFunction.apply(this, arguments);
  };
}
