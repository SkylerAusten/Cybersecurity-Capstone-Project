!function () {
  var e = {
    213: function (e, t, n) {
      var a,
      r,
      i,
      o,
      s,
      l,
      d = function (e) {
        var t = /\blang(?:uage)?-([\w-]+)\b/i,
        n = 0,
        a = {
        },
        r = {
          manual: e.Prism && e.Prism.manual,
          disableWorkerMessageHandler: e.Prism && e.Prism.disableWorkerMessageHandler,
          util: {
            encode: function e(t) {
              return t instanceof i ? new i(t.type, e(t.content), t.alias) : Array.isArray(t) ? t.map(e) : t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/\u00a0/g, ' ')
            },
            type: function (e) {
              return Object.prototype.toString.call(e).slice(8, - 1)
            },
            objId: function (e) {
              return e.__id || Object.defineProperty(e, '__id', {
                value: ++n
              }),
              e.__id
            },
            clone: function e(t, n) {
              var a,
              i;
              switch (n = n || {
                }, r.util.type(t)) {
                case 'Object':
                  if (i = r.util.objId(t), n[i]) return n[i];
                  for (var o in a = {
                  }, n[i] = a, t) t.hasOwnProperty(o) && (a[o] = e(t[o], n));
                  return a;
                case 'Array':
                  return i = r.util.objId(t),
                  n[i] ? n[i] : (a = [
                  ], n[i] = a, t.forEach((function (t, r) {
                    a[r] = e(t, n)
                  })), a);
                default:
                  return t
              }
            },
            getLanguage: function (e) {
              for (; e && !t.test(e.className); ) e = e.parentElement;
              return e ? (e.className.match(t) || [
                ,
                'none'
              ]) [1].toLowerCase() : 'none'
            },
            currentScript: function () {
              if ('undefined' == typeof document) return null;
              if ('currentScript' in document) return document.currentScript;
              try {
                throw new Error
              } catch (a) {
                var e = (/at [^(\r\n]*\((.*):[^:]+:[^:]+\)$/i.exec(a.stack) || [
                ]) [1];
                if (e) {
                  var t = document.getElementsByTagName('script');
                  for (var n in t) if (t[n].src == e) return t[n]
                }
                return null
              }
            },
            isActive: function (e, t, n) {
              for (var a = 'no-' + t; e; ) {
                var r = e.classList;
                if (r.contains(t)) return !0;
                if (r.contains(a)) return !1;
                e = e.parentElement
              }
              return !!n
            }
          },
          languages: {
            plain: a,
            plaintext: a,
            text: a,
            txt: a,
            extend: function (e, t) {
              var n = r.util.clone(r.languages[e]);
              for (var a in t) n[a] = t[a];
              return n
            },
            insertBefore: function (e, t, n, a) {
              var i = (a = a || r.languages) [e],
              o = {
              };
              for (var s in i) if (i.hasOwnProperty(s)) {
                if (s == t) for (var l in n) n.hasOwnProperty(l) && (o[l] = n[l]);
                n.hasOwnProperty(s) || (o[s] = i[s])
              }
              var d = a[e];
              return a[e] = o,
              r.languages.DFS(r.languages, (function (t, n) {
                n === d && t != e && (this[t] = o)
              })),
              o
            },
            DFS: function e(t, n, a, i) {
              i = i || {
              };
              var o = r.util.objId;
              for (var s in t) if (t.hasOwnProperty(s)) {
                n.call(t, s, t[s], a || s);
                var l = t[s],
                d = r.util.type(l);
                'Object' !== d || i[o(l)] ? 'Array' !== d || i[o(l)] || (i[o(l)] = !0, e(l, n, s, i)) : (i[o(l)] = !0, e(l, n, null, i))
              }
            }
          },
          plugins: {
          },
          highlightAll: function (e, t) {
            r.highlightAllUnder(document, e, t)
          },
          highlightAllUnder: function (e, t, n) {
            var a = {
              callback: n,
              container: e,
              selector: 'code[class*="language-"], [class*="language-"] code, code[class*="lang-"], [class*="lang-"] code'
            };
            r.hooks.run('before-highlightall', a),
            a.elements = Array.prototype.slice.apply(a.container.querySelectorAll(a.selector)),
            r.hooks.run('before-all-elements-highlight', a);
            for (var i, o = 0; i = a.elements[o++]; ) r.highlightElement(i, !0 === t, a.callback)
          },
          highlightElement: function (n, a, i) {
            var o = r.util.getLanguage(n),
            s = r.languages[o];
            n.className = n.className.replace(t, '').replace(/\s+/g, ' ') + ' language-' + o;
            var l = n.parentElement;
            l && 'pre' === l.nodeName.toLowerCase() && (l.className = l.className.replace(t, '').replace(/\s+/g, ' ') + ' language-' + o);
            var d = {
              element: n,
              language: o,
              grammar: s,
              code: n.textContent
            };
            function u(e) {
              d.highlightedCode = e,
              r.hooks.run('before-insert', d),
              d.element.innerHTML = d.highlightedCode,
              r.hooks.run('after-highlight', d),
              r.hooks.run('complete', d),
              i && i.call(d.element)
            }
            if (r.hooks.run('before-sanity-check', d), (l = d.element.parentElement) && 'pre' === l.nodeName.toLowerCase() && !l.hasAttribute('tabindex') && l.setAttribute('tabindex', '0'), !d.code) return r.hooks.run('complete', d),
            void (i && i.call(d.element));
            if (r.hooks.run('before-highlight', d), d.grammar) if (a && e.Worker) {
              var c = new Worker(r.filename);
              c.onmessage = function (e) {
                u(e.data)
              },
              c.postMessage(JSON.stringify({
                language: d.language,
                code: d.code,
                immediateClose: !0
              }))
            } else u(r.highlight(d.code, d.grammar, d.language));
             else u(r.util.encode(d.code))
          },
          highlight: function (e, t, n) {
            var a = {
              code: e,
              grammar: t,
              language: n
            };
            return r.hooks.run('before-tokenize', a),
            a.tokens = r.tokenize(a.code, a.grammar),
            r.hooks.run('after-tokenize', a),
            i.stringify(r.util.encode(a.tokens), a.language)
          },
          tokenize: function (e, t) {
            var n = t.rest;
            if (n) {
              for (var a in n) t[a] = n[a];
              delete t.rest
            }
            var u = new s;
            return l(u, u.head, e),
            function e(t, n, a, s, u, c) {
              for (var p in a) if (a.hasOwnProperty(p) && a[p]) {
                var g = a[p];
                g = Array.isArray(g) ? g : [
                  g
                ];
                for (var b = 0; b < g.length; ++b) {
                  if (c && c.cause == p + ',' + b) return;
                  var m = g[b],
                  f = m.inside,
                  h = !!m.lookbehind,
                  E = !!m.greedy,
                  _ = m.alias;
                  if (E && !m.pattern.global) {
                    var S = m.pattern.toString().match(/[imsuy]*$/) [0];
                    m.pattern = RegExp(m.pattern.source, S + 'g')
                  }
                  for (var y = m.pattern || m, v = s.next, A = u; v !== n.tail && !(c && A >= c.reach); A += v.value.length, v = v.next) {
                    var w = v.value;
                    if (n.length > t.length) return;
                    if (!(w instanceof i)) {
                      var T,
                      k = 1;
                      if (E) {
                        if (!(T = o(y, A, t, h))) break;
                        var I = T.index,
                        R = T.index + T[0].length,
                        O = A;
                        for (O += v.value.length; O <= I; ) O += (v = v.next).value.length;
                        if (A = O -= v.value.length, v.value instanceof i) continue;
                        for (var N = v; N !== n.tail && (O < R || 'string' == typeof N.value); N = N.next) k++,
                        O += N.value.length;
                        k--,
                        w = t.slice(A, O),
                        T.index -= A
                      } else if (!(T = o(y, 0, w, h))) continue;
                      I = T.index;
                      var C = T[0],
                      L = w.slice(0, I),
                      D = w.slice(I + C.length),
                      x = A + w.length;
                      c && x > c.reach && (c.reach = x);
                      var P = v.prev;
                      if (L && (P = l(n, P, L), A += L.length), d(n, P, k), v = l(n, P, new i(p, f ? r.tokenize(C, f) : C, _, C)), D && l(n, v, D), 1 < k) {
                        var F = {
                          cause: p + ',' + b,
                          reach: x
                        };
                        e(t, n, a, v.prev, A, F),
                        c && F.reach > c.reach && (c.reach = F.reach)
                      }
                    }
                  }
                }
              }
            }(e, u, t, u.head, 0),
            function (e) {
              for (var t = [
              ], n = e.head.next; n !== e.tail; ) t.push(n.value),
              n = n.next;
              return t
            }(u)
          },
          hooks: {
            all: {
            },
            add: function (e, t) {
              var n = r.hooks.all;
              n[e] = n[e] || [
              ],
              n[e].push(t)
            },
            run: function (e, t) {
              var n = r.hooks.all[e];
              if (n && n.length) for (var a, i = 0; a = n[i++]; ) a(t)
            }
          },
          Token: i
        };
        function i(e, t, n, a) {
          this.type = e,
          this.content = t,
          this.alias = n,
          this.length = 0 | (a || '').length
        }
        function o(e, t, n, a) {
          e.lastIndex = t;
          var r = e.exec(n);
          if (r && a && r[1]) {
            var i = r[1].length;
            r.index += i,
            r[0] = r[0].slice(i)
          }
          return r
        }
        function s() {
          var e = {
            value: null,
            prev: null,
            next: null
          },
          t = {
            value: null,
            prev: e,
            next: null
          };
          e.next = t,
          this.head = e,
          this.tail = t,
          this.length = 0
        }
        function l(e, t, n) {
          var a = t.next,
          r = {
            value: n,
            prev: t,
            next: a
          };
          return t.next = r,
          a.prev = r,
          e.length++,
          r
        }
        function d(e, t, n) {
          for (var a = t.next, r = 0; r < n && a !== e.tail; r++) a = a.next;
          (t.next = a).prev = t,
          e.length -= r
        }
        if (e.Prism = r, i.stringify = function e(t, n) {
          if ('string' == typeof t) return t;
          if (Array.isArray(t)) {
            var a = '';
            return t.forEach((function (t) {
              a += e(t, n)
            })),
            a
          }
          var i = {
            type: t.type,
            content: e(t.content, n),
            tag: 'span',
            classes: [
              'token',
              t.type
            ],
            attributes: {
            },
            language: n
          },
          o = t.alias;
          o && (Array.isArray(o) ? Array.prototype.push.apply(i.classes, o) : i.classes.push(o)),
          r.hooks.run('wrap', i);
          var s = '';
          for (var l in i.attributes) s += ' ' + l + '="' + (i.attributes[l] || '').replace(/"/g, '&quot;') + '"';
          return '<' + i.tag + ' class="' + i.classes.join(' ') + '"' + s + '>' + i.content + '</' + i.tag + '>'
        }, !e.document) return e.addEventListener && (r.disableWorkerMessageHandler || e.addEventListener('message', (function (t) {
          var n = JSON.parse(t.data),
          a = n.language,
          i = n.code,
          o = n.immediateClose;
          e.postMessage(r.highlight(i, r.languages[a], a)),
          o && e.close()
        }), !1)),
        r;
        var u = r.util.currentScript();
        function c() {
          r.manual || r.highlightAll()
        }
        if (u && (r.filename = u.src, u.hasAttribute('data-manual') && (r.manual = !0)), !r.manual) {
          var p = document.readyState;
          'loading' === p || 'interactive' === p && u && u.defer ? document.addEventListener('DOMContentLoaded', c) : window.requestAnimationFrame ? window.requestAnimationFrame(c) : window.setTimeout(c, 16)
        }
        return r
      }('undefined' != typeof window ? window : 'undefined' != typeof WorkerGlobalScope && self instanceof WorkerGlobalScope ? self : {
      });
      e.exports && (e.exports = d),
      void 0 !== n.g && (n.g.Prism = d),
      d.languages.markup = {
        comment: /<!--[\s\S]*?-->/,
        prolog: /<\?[\s\S]+?\?>/,
        doctype: {
          pattern: /<!DOCTYPE(?:[^>"'[\]]|"[^"]*"|'[^']*')+(?:\[(?:[^<"'\]]|"[^"]*"|'[^']*'|<(?!!--)|<!--(?:[^-]|-(?!->))*-->)*\]\s*)?>/i,
          greedy: !0,
          inside: {
            'internal-subset': {
              pattern: /(^[^\[]*\[)[\s\S]+(?=\]>$)/,
              lookbehind: !0,
              greedy: !0,
              inside: null
            },
            string: {
              pattern: /"[^"]*"|'[^']*'/,
              greedy: !0
            },
            punctuation: /^<!|>$|[[\]]/,
            'doctype-tag': /^DOCTYPE/,
            name: /[^\s<>'"]+/
          }
        },
        cdata: /<!\[CDATA\[[\s\S]*?\]\]>/i,
        tag: {
          pattern: /<\/?(?!\d)[^\s>\/=$<%]+(?:\s(?:\s*[^\s>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s'">=]+(?=[\s>]))|(?=[\s/>])))+)?\s*\/?>/,
          greedy: !0,
          inside: {
            tag: {
              pattern: /^<\/?[^\s>\/]+/,
              inside: {
                punctuation: /^<\/?/,
                namespace: /^[^\s>\/:]+:/
              }
            },
            'special-attr': [
            ],
            'attr-value': {
              pattern: /=\s*(?:"[^"]*"|'[^']*'|[^\s'">=]+)/,
              inside: {
                punctuation: [
                  {
                    pattern: /^=/,
                    alias: 'attr-equals'
                  },
                  /"|'/
                ]
              }
            },
            punctuation: /\/?>/,
            'attr-name': {
              pattern: /[^\s>\/]+/,
              inside: {
                namespace: /^[^\s>\/:]+:/
              }
            }
          }
        },
        entity: [
          {
            pattern: /&[\da-z]{1,8};/i,
            alias: 'named-entity'
          },
          /&#x?[\da-f]{1,8};/i
        ]
      },
      d.languages.markup.tag.inside['attr-value'].inside.entity = d.languages.markup.entity,
      d.languages.markup.doctype.inside['internal-subset'].inside = d.languages.markup,
      d.hooks.add('wrap', (function (e) {
        'entity' === e.type && (e.attributes.title = e.content.replace(/&amp;/, '&'))
      })),
      Object.defineProperty(d.languages.markup.tag, 'addInlined', {
        value: function (e, t) {
          var n = {
          };
          n['language-' + t] = {
            pattern: /(^<!\[CDATA\[)[\s\S]+?(?=\]\]>$)/i,
            lookbehind: !0,
            inside: d.languages[t]
          },
          n.cdata = /^<!\[CDATA\[|\]\]>$/i;
          var a = {
            'included-cdata': {
              pattern: /<!\[CDATA\[[\s\S]*?\]\]>/i,
              inside: n
            }
          };
          a['language-' + t] = {
            pattern: /[\s\S]+/,
            inside: d.languages[t]
          };
          var r = {
          };
          r[e] = {
            pattern: RegExp('(<__[^>]*>)(?:<!\\[CDATA\\[(?:[^\\]]|\\](?!\\]>))*\\]\\]>|(?!<!\\[CDATA\\[)[^])*?(?=</__>)'.replace(/__/g, (function () {
              return e
            })), 'i'),
            lookbehind: !0,
            greedy: !0,
            inside: a
          },
          d.languages.insertBefore('markup', 'cdata', r)
        }
      }),
      Object.defineProperty(d.languages.markup.tag, 'addAttribute', {
        value: function (e, t) {
          d.languages.markup.tag.inside['special-attr'].push({
            pattern: RegExp('(^|["\'\\s])(?:' + e + ')\\s*=\\s*(?:"[^"]*"|\'[^\']*\'|[^\\s\'">=]+(?=[\\s>]))', 'i'),
            lookbehind: !0,
            inside: {
              'attr-name': /^[^\s=]+/,
              'attr-value': {
                pattern: /=[\s\S]+/,
                inside: {
                  value: {
                    pattern: /(^=\s*(["']|(?!["'])))\S[\s\S]*(?=\2$)/,
                    lookbehind: !0,
                    alias: [
                      t,
                      'language-' + t
                    ],
                    inside: d.languages[t]
                  },
                  punctuation: [
                    {
                      pattern: /^=/,
                      alias: 'attr-equals'
                    },
                    /"|'/
                  ]
                }
              }
            }
          })
        }
      }),
      d.languages.html = d.languages.markup,
      d.languages.mathml = d.languages.markup,
      d.languages.svg = d.languages.markup,
      d.languages.xml = d.languages.extend('markup', {
      }),
      d.languages.ssml = d.languages.xml,
      d.languages.atom = d.languages.xml,
      d.languages.rss = d.languages.xml,
      function (e) {
        var t = /(?:"(?:\\(?:\r\n|[\s\S])|[^"\\\r\n])*"|'(?:\\(?:\r\n|[\s\S])|[^'\\\r\n])*')/;
        e.languages.css = {
          comment: /\/\*[\s\S]*?\*\//,
          atrule: {
            pattern: /@[\w-](?:[^;{\s]|\s+(?![\s{]))*(?:;|(?=\s*\{))/,
            inside: {
              rule: /^@[\w-]+/,
              'selector-function-argument': {
                pattern: /(\bselector\s*\(\s*(?![\s)]))(?:[^()\s]|\s+(?![\s)])|\((?:[^()]|\([^()]*\))*\))+(?=\s*\))/,
                lookbehind: !0,
                alias: 'selector'
              },
              keyword: {
                pattern: /(^|[^\w-])(?:and|not|only|or)(?![\w-])/,
                lookbehind: !0
              }
            }
          },
          url: {
            pattern: RegExp('\\burl\\((?:' + t.source + '|(?:[^\\\\\r\n()"\']|\\\\[^])*)\\)', 'i'),
            greedy: !0,
            inside: {
              function : /^url/i,
              punctuation: /^\(|\)$/,
              string: {
                pattern: RegExp('^' + t.source + '$'),
                alias: 'url'
              }
            }
          },
          selector: {
            pattern: RegExp('(^|[{}\\s])[^{}\\s](?:[^{};"\'\\s]|\\s+(?![\\s{])|' + t.source + ')*(?=\\s*\\{)'),
            lookbehind: !0
          },
          string: {
            pattern: t,
            greedy: !0
          },
          property: {
            pattern: /(^|[^-\w\xA0-\uFFFF])(?!\s)[-_a-z\xA0-\uFFFF](?:(?!\s)[-\w\xA0-\uFFFF])*(?=\s*:)/i,
            lookbehind: !0
          },
          important: /!important\b/i,
          function : {
            pattern: /(^|[^-a-z0-9])[-a-z0-9]+(?=\()/i,
            lookbehind: !0
          },
          punctuation: /[(){};:,]/
        },
        e.languages.css.atrule.inside.rest = e.languages.css;
        var n = e.languages.markup;
        n && (n.tag.addInlined('style', 'css'), n.tag.addAttribute('style', 'css'))
      }(d),
      d.languages.clike = {
        comment: [
          {
            pattern: /(^|[^\\])\/\*[\s\S]*?(?:\*\/|$)/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^\\:])\/\/.*/,
            lookbehind: !0,
            greedy: !0
          }
        ],
        string: {
          pattern: /(["'])(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/,
          greedy: !0
        },
        'class-name': {
          pattern: /(\b(?:class|interface|extends|implements|trait|instanceof|new)\s+|\bcatch\s+\()[\w.\\]+/i,
          lookbehind: !0,
          inside: {
            punctuation: /[.\\]/
          }
        },
        keyword: /\b(?:if|else|while|do|for|return|in|instanceof|function|new|try|throw|catch|finally|null|break|continue)\b/,
        boolean: /\b(?:true|false)\b/,
        function : /\b\w+(?=\()/,
        number: /\b0x[\da-f]+\b|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[+-]?\d+)?/i,
        operator: /[<>]=?|[!=]=?=?|--?|\+\+?|&&?|\|\|?|[?*/~^%]/,
        punctuation: /[{}[\];(),.:]/
      },
      d.languages.javascript = d.languages.extend('clike', {
        'class-name': [
          d.languages.clike['class-name'],
          {
            pattern: /(^|[^$\w\xA0-\uFFFF])(?!\s)[_$A-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\.(?:prototype|constructor))/,
            lookbehind: !0
          }
        ],
        keyword: [
          {
            pattern: /((?:^|\})\s*)catch\b/,
            lookbehind: !0
          },
          {
            pattern: /(^|[^.]|\.\.\.\s*)\b(?:as|assert(?=\s*\{)|async(?=\s*(?:function\b|\(|[$\w\xA0-\uFFFF]|$))|await|break|case|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally(?=\s*(?:\{|$))|for|from(?=\s*(?:['"]|$))|function|(?:get|set)(?=\s*(?:[#\[$\w\xA0-\uFFFF]|$))|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)\b/,
            lookbehind: !0
          }
        ],
        function : /#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*(?:\.\s*(?:apply|bind|call)\s*)?\()/,
        number: /\b(?:(?:0[xX](?:[\dA-Fa-f](?:_[\dA-Fa-f])?)+|0[bB](?:[01](?:_[01])?)+|0[oO](?:[0-7](?:_[0-7])?)+)n?|(?:\d(?:_\d)?)+n|NaN|Infinity)\b|(?:\b(?:\d(?:_\d)?)+\.?(?:\d(?:_\d)?)*|\B\.(?:\d(?:_\d)?)+)(?:[Ee][+-]?(?:\d(?:_\d)?)+)?/,
        operator: /--|\+\+|\*\*=?|=>|&&=?|\|\|=?|[!=]==|<<=?|>>>?=?|[-+*/%&|^!=<>]=?|\.{3}|\?\?=?|\?\.?|[~:]/
      }),
      d.languages.javascript['class-name'][0].pattern = /(\b(?:class|interface|extends|implements|instanceof|new)\s+)[\w.\\]+/,
      d.languages.insertBefore('javascript', 'keyword', {
        regex: {
          pattern: /((?:^|[^$\w\xA0-\uFFFF."'\])\s]|\b(?:return|yield))\s*)\/(?:\[(?:[^\]\\\r\n]|\\.)*\]|\\.|[^/\\\[\r\n])+\/[dgimyus]{0,7}(?=(?:\s|\/\*(?:[^*]|\*(?!\/))*\*\/)*(?:$|[\r\n,.;:})\]]|\/\/))/,
          lookbehind: !0,
          greedy: !0,
          inside: {
            'regex-source': {
              pattern: /^(\/)[\s\S]+(?=\/[a-z]*$)/,
              lookbehind: !0,
              alias: 'language-regex',
              inside: d.languages.regex
            },
            'regex-delimiter': /^\/|\/$/,
            'regex-flags': /^[a-z]+$/
          }
        },
        'function-variable': {
          pattern: /#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*[=:]\s*(?:async\s*)?(?:\bfunction\b|(?:\((?:[^()]|\([^()]*\))*\)|(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*)\s*=>))/,
          alias: 'function'
        },
        parameter: [
          {
            pattern: /(function(?:\s+(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*)?\s*\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\))/,
            lookbehind: !0,
            inside: d.languages.javascript
          },
          {
            pattern: /(^|[^$\w\xA0-\uFFFF])(?!\s)[_$a-z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*=>)/i,
            lookbehind: !0,
            inside: d.languages.javascript
          },
          {
            pattern: /(\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\)\s*=>)/,
            lookbehind: !0,
            inside: d.languages.javascript
          },
          {
            pattern: /((?:\b|\s|^)(?!(?:as|async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)(?![$\w\xA0-\uFFFF]))(?:(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*\s*)\(\s*|\]\s*\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\)\s*\{)/,
            lookbehind: !0,
            inside: d.languages.javascript
          }
        ],
        constant: /\b[A-Z](?:[A-Z_]|\dx?)*\b/
      }),
      d.languages.insertBefore('javascript', 'string', {
        hashbang: {
          pattern: /^#!.*/,
          greedy: !0,
          alias: 'comment'
        },
        'template-string': {
          pattern: /`(?:\\[\s\S]|\$\{(?:[^{}]|\{(?:[^{}]|\{[^}]*\})*\})+\}|(?!\$\{)[^\\`])*`/,
          greedy: !0,
          inside: {
            'template-punctuation': {
              pattern: /^`|`$/,
              alias: 'string'
            },
            interpolation: {
              pattern: /((?:^|[^\\])(?:\\{2})*)\$\{(?:[^{}]|\{(?:[^{}]|\{[^}]*\})*\})+\}/,
              lookbehind: !0,
              inside: {
                'interpolation-punctuation': {
                  pattern: /^\$\{|\}$/,
                  alias: 'punctuation'
                },
                rest: d.languages.javascript
              }
            },
            string: /[\s\S]+/
          }
        }
      }),
      d.languages.markup && (d.languages.markup.tag.addInlined('script', 'javascript'), d.languages.markup.tag.addAttribute('on(?:abort|blur|change|click|composition(?:end|start|update)|dblclick|error|focus(?:in|out)?|key(?:down|up)|load|mouse(?:down|enter|leave|move|out|over|up)|reset|resize|scroll|select|slotchange|submit|unload|wheel)', 'javascript')),
      d.languages.js = d.languages.javascript,
      d.languages.actionscript = d.languages.extend('javascript', {
        keyword: /\b(?:as|break|case|catch|class|const|default|delete|do|else|extends|finally|for|function|if|implements|import|in|instanceof|interface|internal|is|native|new|null|package|private|protected|public|return|super|switch|this|throw|try|typeof|use|var|void|while|with|dynamic|each|final|get|include|namespace|override|set|static)\b/,
        operator: /\+\+|--|(?:[+\-*\/%^]|&&?|\|\|?|<<?|>>?>?|[!=]=?)=?|[~?@]/
      }),
      d.languages.actionscript['class-name'].alias = 'function',
      d.languages.markup && d.languages.insertBefore('actionscript', 'string', {
        xml: {
          pattern: /(^|[^.])<\/?\w+(?:\s+[^\s>\/=]+=("|')(?:\\[\s\S]|(?!\2)[^\\])*\2)*\s*\/?>/,
          lookbehind: !0,
          inside: d.languages.markup
        }
      }),
      d.languages.apacheconf = {
        comment: /#.*/,
        'directive-inline': {
          pattern: /(^[\t ]*)\b(?:AcceptFilter|AcceptPathInfo|AccessFileName|Action|Add(?:Alt|AltByEncoding|AltByType|Charset|DefaultCharset|Description|Encoding|Handler|Icon|IconByEncoding|IconByType|InputFilter|Language|ModuleInfo|OutputFilter|OutputFilterByType|Type)|Alias|AliasMatch|Allow(?:CONNECT|EncodedSlashes|Methods|Override|OverrideList)?|Anonymous(?:_LogEmail|_MustGiveEmail|_NoUserID|_VerifyEmail)?|AsyncRequestWorkerFactor|Auth(?:BasicAuthoritative|BasicFake|BasicProvider|BasicUseDigestAlgorithm|DBDUserPWQuery|DBDUserRealmQuery|DBMGroupFile|DBMType|DBMUserFile|Digest(?:Algorithm|Domain|NonceLifetime|Provider|Qop|ShmemSize)|Form(?:Authoritative|Body|DisableNoStore|FakeBasicAuth|Location|LoginRequiredLocation|LoginSuccessLocation|LogoutLocation|Method|Mimetype|Password|Provider|SitePassphrase|Size|Username)|GroupFile|LDAP(?:AuthorizePrefix|BindAuthoritative|BindDN|BindPassword|CharsetConfig|CompareAsUser|CompareDNOnServer|DereferenceAliases|GroupAttribute|GroupAttributeIsDN|InitialBindAsUser|InitialBindPattern|MaxSubGroupDepth|RemoteUserAttribute|RemoteUserIsDN|SearchAsUser|SubGroupAttribute|SubGroupClass|Url)|Merging|Name|Type|UserFile|nCache(?:Context|Enable|ProvideFor|SOCache|Timeout)|nzFcgiCheckAuthnProvider|nzFcgiDefineProvider|zDBDLoginToReferer|zDBDQuery|zDBDRedirectQuery|zDBMType|zSendForbiddenOnFailure)|BalancerGrowth|BalancerInherit|BalancerMember|BalancerPersist|BrowserMatch|BrowserMatchNoCase|BufferSize|BufferedLogs|CGIDScriptTimeout|CGIMapExtension|Cache(?:DefaultExpire|DetailHeader|DirLength|DirLevels|Disable|Enable|File|Header|IgnoreCacheControl|IgnoreHeaders|IgnoreNoLastMod|IgnoreQueryString|IgnoreURLSessionIdentifiers|KeyBaseURL|LastModifiedFactor|Lock|LockMaxAge|LockPath|MaxExpire|MaxFileSize|MinExpire|MinFileSize|NegotiatedDocs|QuickHandler|ReadSize|ReadTime|Root|Socache(?:MaxSize|MaxTime|MinTime|ReadSize|ReadTime)?|StaleOnError|StoreExpired|StoreNoStore|StorePrivate)|CharsetDefault|CharsetOptions|CharsetSourceEnc|CheckCaseOnly|CheckSpelling|ChrootDir|ContentDigest|CookieDomain|CookieExpires|CookieName|CookieStyle|CookieTracking|CoreDumpDirectory|CustomLog|DBDExptime|DBDInitSQL|DBDKeep|DBDMax|DBDMin|DBDParams|DBDPersist|DBDPrepareSQL|DBDriver|DTracePrivileges|Dav|DavDepthInfinity|DavGenericLockDB|DavLockDB|DavMinTimeout|DefaultIcon|DefaultLanguage|DefaultRuntimeDir|DefaultType|Define|Deflate(?:BufferSize|CompressionLevel|FilterNote|InflateLimitRequestBody|InflateRatio(?:Burst|Limit)|MemLevel|WindowSize)|Deny|DirectoryCheckHandler|DirectoryIndex|DirectoryIndexRedirect|DirectorySlash|DocumentRoot|DumpIOInput|DumpIOOutput|EnableExceptionHook|EnableMMAP|EnableSendfile|Error|ErrorDocument|ErrorLog|ErrorLogFormat|Example|ExpiresActive|ExpiresByType|ExpiresDefault|ExtFilterDefine|ExtFilterOptions|ExtendedStatus|FallbackResource|FileETag|FilterChain|FilterDeclare|FilterProtocol|FilterProvider|FilterTrace|ForceLanguagePriority|ForceType|ForensicLog|GprofDir|GracefulShutdownTimeout|Group|Header|HeaderName|Heartbeat(?:Address|Listen|MaxServers|Storage)|HostnameLookups|ISAPI(?:AppendLogToErrors|AppendLogToQuery|CacheFile|FakeAsync|LogNotSupported|ReadAheadBuffer)|IdentityCheck|IdentityCheckTimeout|ImapBase|ImapDefault|ImapMenu|Include|IncludeOptional|Index(?:HeadInsert|Ignore|IgnoreReset|Options|OrderDefault|StyleSheet)|InputSed|KeepAlive|KeepAliveTimeout|KeptBodySize|LDAP(?:CacheEntries|CacheTTL|ConnectionPoolTTL|ConnectionTimeout|LibraryDebug|OpCacheEntries|OpCacheTTL|ReferralHopLimit|Referrals|Retries|RetryDelay|SharedCacheFile|SharedCacheSize|Timeout|TrustedClientCert|TrustedGlobalCert|TrustedMode|VerifyServerCert)|LanguagePriority|Limit(?:InternalRecursion|Request(?:Body|FieldSize|Fields|Line)|XMLRequestBody)|Listen|ListenBackLog|LoadFile|LoadModule|LogFormat|LogLevel|LogMessage|LuaAuthzProvider|LuaCodeCache|Lua(?:Hook(?:AccessChecker|AuthChecker|CheckUserID|Fixups|InsertFilter|Log|MapToStorage|TranslateName|TypeChecker)|Inherit|InputFilter|MapHandler|OutputFilter|PackageCPath|PackagePath|QuickHandler|Root|Scope)|MMapFile|Max(?:ConnectionsPerChild|KeepAliveRequests|MemFree|RangeOverlaps|RangeReversals|Ranges|RequestWorkers|SpareServers|SpareThreads|Threads)|MergeTrailers|MetaDir|MetaFiles|MetaSuffix|MimeMagicFile|MinSpareServers|MinSpareThreads|ModMimeUsePathInfo|ModemStandard|MultiviewsMatch|Mutex|NWSSLTrustedCerts|NWSSLUpgradeable|NameVirtualHost|NoProxy|Options|Order|OutputSed|PassEnv|PidFile|PrivilegesMode|Protocol|ProtocolEcho|Proxy(?:AddHeaders|BadHeader|Block|Domain|ErrorOverride|ExpressDBMFile|ExpressDBMType|ExpressEnable|FtpDirCharset|FtpEscapeWildcards|FtpListOnWildcard|HTML(?:BufSize|CharsetOut|DocType|Enable|Events|Extended|Fixups|Interp|Links|Meta|StripComments|URLMap)|IOBufferSize|MaxForwards|Pass(?:Inherit|InterpolateEnv|Match|Reverse|ReverseCookieDomain|ReverseCookiePath)?|PreserveHost|ReceiveBufferSize|Remote|RemoteMatch|Requests|SCGIInternalRedirect|SCGISendfile|Set|SourceAddress|Status|Timeout|Via)|RLimitCPU|RLimitMEM|RLimitNPROC|ReadmeName|ReceiveBufferSize|Redirect|RedirectMatch|RedirectPermanent|RedirectTemp|ReflectorHeader|RemoteIP(?:Header|InternalProxy|InternalProxyList|ProxiesHeader|TrustedProxy|TrustedProxyList)|RemoveCharset|RemoveEncoding|RemoveHandler|RemoveInputFilter|RemoveLanguage|RemoveOutputFilter|RemoveType|RequestHeader|RequestReadTimeout|Require|Rewrite(?:Base|Cond|Engine|Map|Options|Rule)|SSIETag|SSIEndTag|SSIErrorMsg|SSILastModified|SSILegacyExprParser|SSIStartTag|SSITimeFormat|SSIUndefinedEcho|SSL(?:CACertificateFile|CACertificatePath|CADNRequestFile|CADNRequestPath|CARevocationCheck|CARevocationFile|CARevocationPath|CertificateChainFile|CertificateFile|CertificateKeyFile|CipherSuite|Compression|CryptoDevice|Engine|FIPS|HonorCipherOrder|InsecureRenegotiation|OCSP(?:DefaultResponder|Enable|OverrideResponder|ResponderTimeout|ResponseMaxAge|ResponseTimeSkew|UseRequestNonce)|OpenSSLConfCmd|Options|PassPhraseDialog|Protocol|Proxy(?:CACertificateFile|CACertificatePath|CARevocation(?:Check|File|Path)|CheckPeer(?:CN|Expire|Name)|CipherSuite|Engine|MachineCertificate(?:ChainFile|File|Path)|Protocol|Verify|VerifyDepth)|RandomSeed|RenegBufferSize|Require|RequireSSL|SRPUnknownUserSeed|SRPVerifierFile|Session(?:Cache|CacheTimeout|TicketKeyFile|Tickets)|Stapling(?:Cache|ErrorCacheTimeout|FakeTryLater|ForceURL|ResponderTimeout|ResponseMaxAge|ResponseTimeSkew|ReturnResponderErrors|StandardCacheTimeout)|StrictSNIVHostCheck|UseStapling|UserName|VerifyClient|VerifyDepth)|Satisfy|ScoreBoardFile|Script(?:Alias|AliasMatch|InterpreterSource|Log|LogBuffer|LogLength|Sock)?|SecureListen|SeeRequestTail|SendBufferSize|Server(?:Admin|Alias|Limit|Name|Path|Root|Signature|Tokens)|Session(?:Cookie(?:Name|Name2|Remove)|Crypto(?:Cipher|Driver|Passphrase|PassphraseFile)|DBD(?:CookieName|CookieName2|CookieRemove|DeleteLabel|InsertLabel|PerUser|SelectLabel|UpdateLabel)|Env|Exclude|Header|Include|MaxAge)?|SetEnv|SetEnvIf|SetEnvIfExpr|SetEnvIfNoCase|SetHandler|SetInputFilter|SetOutputFilter|StartServers|StartThreads|Substitute|Suexec|SuexecUserGroup|ThreadLimit|ThreadStackSize|ThreadsPerChild|TimeOut|TraceEnable|TransferLog|TypesConfig|UnDefine|UndefMacro|UnsetEnv|Use|UseCanonicalName|UseCanonicalPhysicalPort|User|UserDir|VHostCGIMode|VHostCGIPrivs|VHostGroup|VHostPrivs|VHostSecure|VHostUser|Virtual(?:DocumentRoot|ScriptAlias)(?:IP)?|WatchdogInterval|XBitHack|xml2EncAlias|xml2EncDefault|xml2StartParse)\b/im,
          lookbehind: !0,
          alias: 'property'
        },
        'directive-block': {
          pattern: /<\/?\b(?:Auth[nz]ProviderAlias|Directory|DirectoryMatch|Else|ElseIf|Files|FilesMatch|If|IfDefine|IfModule|IfVersion|Limit|LimitExcept|Location|LocationMatch|Macro|Proxy|Require(?:All|Any|None)|VirtualHost)\b.*>/i,
          inside: {
            'directive-block': {
              pattern: /^<\/?\w+/,
              inside: {
                punctuation: /^<\/?/
              },
              alias: 'tag'
            },
            'directive-block-parameter': {
              pattern: /.*[^>]/,
              inside: {
                punctuation: /:/,
                string: {
                  pattern: /("|').*\1/,
                  inside: {
                    variable: /[$%]\{?(?:\w\.?[-+:]?)+\}?/
                  }
                }
              },
              alias: 'attr-value'
            },
            punctuation: />/
          },
          alias: 'tag'
        },
        'directive-flags': {
          pattern: /\[(?:[\w=],?)+\]/,
          alias: 'keyword'
        },
        string: {
          pattern: /("|').*\1/,
          inside: {
            variable: /[$%]\{?(?:\w\.?[-+:]?)+\}?/
          }
        },
        variable: /[$%]\{?(?:\w\.?[-+:]?)+\}?/,
        regex: /\^?.*\$|\^.*\$?/
      },
      d.languages.applescript = {
        comment: [
          /\(\*(?:\(\*(?:[^*]|\*(?!\)))*\*\)|(?!\(\*)[\s\S])*?\*\)/,
          /--.+/,
          /#.+/
        ],
        string: /"(?:\\.|[^"\\\r\n])*"/,
        number: /(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e-?\d+)?\b/i,
        operator: [
          /[&=≠≤≥*+\-\/÷^]|[<>]=?/,
          /\b(?:(?:start|begin|end)s? with|(?:(?:does not|doesn't) contain|contains?)|(?:is|isn't|is not) (?:in|contained by)|(?:(?:is|isn't|is not) )?(?:greater|less) than(?: or equal)?(?: to)?|(?:(?:does not|doesn't) come|comes) (?:before|after)|(?:is|isn't|is not) equal(?: to)?|(?:(?:does not|doesn't) equal|equals|equal to|isn't|is not)|(?:a )?(?:ref(?: to)?|reference to)|(?:and|or|div|mod|as|not))\b/
        ],
        keyword: /\b(?:about|above|after|against|apart from|around|aside from|at|back|before|beginning|behind|below|beneath|beside|between|but|by|considering|continue|copy|does|eighth|else|end|equal|error|every|exit|false|fifth|first|for|fourth|from|front|get|given|global|if|ignoring|in|instead of|into|is|it|its|last|local|me|middle|my|ninth|of|on|onto|out of|over|prop|property|put|repeat|return|returning|second|set|seventh|since|sixth|some|tell|tenth|that|the|then|third|through|thru|timeout|times|to|transaction|true|try|until|where|while|whose|with|without)\b/,
        class : {
          pattern: /\b(?:alias|application|boolean|class|constant|date|file|integer|list|number|POSIX file|real|record|reference|RGB color|script|text|centimetres|centimeters|feet|inches|kilometres|kilometers|metres|meters|miles|yards|square feet|square kilometres|square kilometers|square metres|square meters|square miles|square yards|cubic centimetres|cubic centimeters|cubic feet|cubic inches|cubic metres|cubic meters|cubic yards|gallons|litres|liters|quarts|grams|kilograms|ounces|pounds|degrees Celsius|degrees Fahrenheit|degrees Kelvin)\b/,
          alias: 'builtin'
        },
        punctuation: /[{}():,¬«»《》]/
      },
      function (e) {
        var t = '\\b(?:BASH|BASHOPTS|BASH_ALIASES|BASH_ARGC|BASH_ARGV|BASH_CMDS|BASH_COMPLETION_COMPAT_DIR|BASH_LINENO|BASH_REMATCH|BASH_SOURCE|BASH_VERSINFO|BASH_VERSION|COLORTERM|COLUMNS|COMP_WORDBREAKS|DBUS_SESSION_BUS_ADDRESS|DEFAULTS_PATH|DESKTOP_SESSION|DIRSTACK|DISPLAY|EUID|GDMSESSION|GDM_LANG|GNOME_KEYRING_CONTROL|GNOME_KEYRING_PID|GPG_AGENT_INFO|GROUPS|HISTCONTROL|HISTFILE|HISTFILESIZE|HISTSIZE|HOME|HOSTNAME|HOSTTYPE|IFS|INSTANCE|JOB|LANG|LANGUAGE|LC_ADDRESS|LC_ALL|LC_IDENTIFICATION|LC_MEASUREMENT|LC_MONETARY|LC_NAME|LC_NUMERIC|LC_PAPER|LC_TELEPHONE|LC_TIME|LESSCLOSE|LESSOPEN|LINES|LOGNAME|LS_COLORS|MACHTYPE|MAILCHECK|MANDATORY_PATH|NO_AT_BRIDGE|OLDPWD|OPTERR|OPTIND|ORBIT_SOCKETDIR|OSTYPE|PAPERSIZE|PATH|PIPESTATUS|PPID|PS1|PS2|PS3|PS4|PWD|RANDOM|REPLY|SECONDS|SELINUX_INIT|SESSION|SESSIONTYPE|SESSION_MANAGER|SHELL|SHELLOPTS|SHLVL|SSH_AUTH_SOCK|TERM|UID|UPSTART_EVENTS|UPSTART_INSTANCE|UPSTART_JOB|UPSTART_SESSION|USER|WINDOWID|XAUTHORITY|XDG_CONFIG_DIRS|XDG_CURRENT_DESKTOP|XDG_DATA_DIRS|XDG_GREETER_DATA_DIR|XDG_MENU_PREFIX|XDG_RUNTIME_DIR|XDG_SEAT|XDG_SEAT_PATH|XDG_SESSION_DESKTOP|XDG_SESSION_ID|XDG_SESSION_PATH|XDG_SESSION_TYPE|XDG_VTNR|XMODIFIERS)\\b',
        n = {
          pattern: /(^(["']?)\w+\2)[ \t]+\S.*/,
          lookbehind: !0,
          alias: 'punctuation',
          inside: null
        },
        a = {
          bash: n,
          environment: {
            pattern: RegExp('\\$' + t),
            alias: 'constant'
          },
          variable: [
            {
              pattern: /\$?\(\([\s\S]+?\)\)/,
              greedy: !0,
              inside: {
                variable: [
                  {
                    pattern: /(^\$\(\([\s\S]+)\)\)/,
                    lookbehind: !0
                  },
                  /^\$\(\(/
                ],
                number: /\b0x[\dA-Fa-f]+\b|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:[Ee]-?\d+)?/,
                operator: /--|\+\+|\*\*=?|<<=?|>>=?|&&|\|\||[=!+\-*/%<>^&|]=?|[?~:]/,
                punctuation: /\(\(?|\)\)?|,|;/
              }
            },
            {
              pattern: /\$\((?:\([^)]+\)|[^()])+\)|`[^`]+`/,
              greedy: !0,
              inside: {
                variable: /^\$\(|^`|\)$|`$/
              }
            },
            {
              pattern: /\$\{[^}]+\}/,
              greedy: !0,
              inside: {
                operator: /:[-=?+]?|[!\/]|##?|%%?|\^\^?|,,?/,
                punctuation: /[\[\]]/,
                environment: {
                  pattern: RegExp('(\\{)' + t),
                  lookbehind: !0,
                  alias: 'constant'
                }
              }
            },
            /\$(?:\w+|[#?*!@$])/
          ],
          entity: /\\(?:[abceEfnrtv\\"]|O?[0-7]{1,3}|x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/
        };
        e.languages.bash = {
          shebang: {
            pattern: /^#!\s*\/.*/,
            alias: 'important'
          },
          comment: {
            pattern: /(^|[^"{\\$])#.*/,
            lookbehind: !0
          },
          'function-name': [
            {
              pattern: /(\bfunction\s+)[\w-]+(?=(?:\s*\(?:\s*\))?\s*\{)/,
              lookbehind: !0,
              alias: 'function'
            },
            {
              pattern: /\b[\w-]+(?=\s*\(\s*\)\s*\{)/,
              alias: 'function'
            }
          ],
          'for-or-select': {
            pattern: /(\b(?:for|select)\s+)\w+(?=\s+in\s)/,
            alias: 'variable',
            lookbehind: !0
          },
          'assign-left': {
            pattern: /(^|[\s;|&]|[<>]\()\w+(?=\+?=)/,
            inside: {
              environment: {
                pattern: RegExp('(^|[\\s;|&]|[<>]\\()' + t),
                lookbehind: !0,
                alias: 'constant'
              }
            },
            alias: 'variable',
            lookbehind: !0
          },
          string: [
            {
              pattern: /((?:^|[^<])<<-?\s*)(\w+)\s[\s\S]*?(?:\r?\n|\r)\2/,
              lookbehind: !0,
              greedy: !0,
              inside: a
            },
            {
              pattern: /((?:^|[^<])<<-?\s*)(["'])(\w+)\2\s[\s\S]*?(?:\r?\n|\r)\3/,
              lookbehind: !0,
              greedy: !0,
              inside: {
                bash: n
              }
            },
            {
              pattern: /(^|[^\\](?:\\\\)*)"(?:\\[\s\S]|\$\([^)]+\)|\$(?!\()|`[^`]+`|[^"\\`$])*"/,
              lookbehind: !0,
              greedy: !0,
              inside: a
            },
            {
              pattern: /(^|[^$\\])'[^']*'/,
              lookbehind: !0,
              greedy: !0
            },
            {
              pattern: /\$'(?:[^'\\]|\\[\s\S])*'/,
              greedy: !0,
              inside: {
                entity: a.entity
              }
            }
          ],
          environment: {
            pattern: RegExp('\\$?' + t),
            alias: 'constant'
          },
          variable: a.variable,
          function : {
            pattern: /(^|[\s;|&]|[<>]\()(?:add|apropos|apt|aptitude|apt-cache|apt-get|aspell|automysqlbackup|awk|basename|bash|bc|bconsole|bg|bzip2|cal|cat|cfdisk|chgrp|chkconfig|chmod|chown|chroot|cksum|clear|cmp|column|comm|composer|cp|cron|crontab|csplit|curl|cut|date|dc|dd|ddrescue|debootstrap|df|diff|diff3|dig|dir|dircolors|dirname|dirs|dmesg|du|egrep|eject|env|ethtool|expand|expect|expr|fdformat|fdisk|fg|fgrep|file|find|fmt|fold|format|free|fsck|ftp|fuser|gawk|git|gparted|grep|groupadd|groupdel|groupmod|groups|grub-mkconfig|gzip|halt|head|hg|history|host|hostname|htop|iconv|id|ifconfig|ifdown|ifup|import|install|ip|jobs|join|kill|killall|less|link|ln|locate|logname|logrotate|look|lpc|lpr|lprint|lprintd|lprintq|lprm|ls|lsof|lynx|make|man|mc|mdadm|mkconfig|mkdir|mke2fs|mkfifo|mkfs|mkisofs|mknod|mkswap|mmv|more|most|mount|mtools|mtr|mutt|mv|nano|nc|netstat|nice|nl|nohup|notify-send|npm|nslookup|op|open|parted|passwd|paste|pathchk|ping|pkill|pnpm|popd|pr|printcap|printenv|ps|pushd|pv|quota|quotacheck|quotactl|ram|rar|rcp|reboot|remsync|rename|renice|rev|rm|rmdir|rpm|rsync|scp|screen|sdiff|sed|sendmail|seq|service|sftp|sh|shellcheck|shuf|shutdown|sleep|slocate|sort|split|ssh|stat|strace|su|sudo|sum|suspend|swapon|sync|tac|tail|tar|tee|time|timeout|top|touch|tr|traceroute|tsort|tty|umount|uname|unexpand|uniq|units|unrar|unshar|unzip|update-grub|uptime|useradd|userdel|usermod|users|uudecode|uuencode|v|vdir|vi|vim|virsh|vmstat|wait|watch|wc|wget|whereis|which|who|whoami|write|xargs|xdg-open|yarn|yes|zenity|zip|zsh|zypper)(?=$|[)\s;|&])/,
            lookbehind: !0
          },
          keyword: {
            pattern: /(^|[\s;|&]|[<>]\()(?:if|then|else|elif|fi|for|while|in|case|esac|function|select|do|done|until)(?=$|[)\s;|&])/,
            lookbehind: !0
          },
          builtin: {
            pattern: /(^|[\s;|&]|[<>]\()(?:\.|:|break|cd|continue|eval|exec|exit|export|getopts|hash|pwd|readonly|return|shift|test|times|trap|umask|unset|alias|bind|builtin|caller|command|declare|echo|enable|help|let|local|logout|mapfile|printf|read|readarray|source|type|typeset|ulimit|unalias|set|shopt)(?=$|[)\s;|&])/,
            lookbehind: !0,
            alias: 'class-name'
          },
          boolean: {
            pattern: /(^|[\s;|&]|[<>]\()(?:true|false)(?=$|[)\s;|&])/,
            lookbehind: !0
          },
          'file-descriptor': {
            pattern: /\B&\d\b/,
            alias: 'important'
          },
          operator: {
            pattern: /\d?<>|>\||\+=|=[=~]?|!=?|<<[<-]?|[&\d]?>>|\d[<>]&?|[<>][&=]?|&[>&]?|\|[&|]?/,
            inside: {
              'file-descriptor': {
                pattern: /^\d/,
                alias: 'important'
              }
            }
          },
          punctuation: /\$?\(\(?|\)\)?|\.\.|[{}[\];\\]/,
          number: {
            pattern: /(^|\s)(?:[1-9]\d*|0)(?:[.,]\d+)?\b/,
            lookbehind: !0
          }
        },
        n.inside = e.languages.bash;
        for (var r = [
          'comment',
          'function-name',
          'for-or-select',
          'assign-left',
          'string',
          'environment',
          'function',
          'keyword',
          'builtin',
          'boolean',
          'file-descriptor',
          'operator',
          'punctuation',
          'number'
        ], i = a.variable[1].inside, o = 0; o < r.length; o++) i[r[o]] = e.languages.bash[r[o]];
        e.languages.shell = e.languages.bash
      }(d),
      d.languages.c = d.languages.extend('clike', {
        comment: {
          pattern: /\/\/(?:[^\r\n\\]|\\(?:\r\n?|\n|(?![\r\n])))*|\/\*[\s\S]*?(?:\*\/|$)/,
          greedy: !0
        },
        'class-name': {
          pattern: /(\b(?:enum|struct)\s+(?:__attribute__\s*\(\([\s\S]*?\)\)\s*)?)\w+|\b[a-z]\w*_t\b/,
          lookbehind: !0
        },
        keyword: /\b(?:__attribute__|_Alignas|_Alignof|_Atomic|_Bool|_Complex|_Generic|_Imaginary|_Noreturn|_Static_assert|_Thread_local|asm|typeof|inline|auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|int|long|register|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while)\b/,
        function : /\b[a-z_]\w*(?=\s*\()/i,
        number: /(?:\b0x(?:[\da-f]+(?:\.[\da-f]*)?|\.[\da-f]+)(?:p[+-]?\d+)?|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[+-]?\d+)?)[ful]{0,4}/i,
        operator: />>=?|<<=?|->|([-+&|:])\1|[?:~]|[-+*/%&|^!=<>]=?/
      }),
      d.languages.insertBefore('c', 'string', {
        macro: {
          pattern: /(^[\t ]*)#\s*[a-z](?:[^\r\n\\/]|\/(?!\*)|\/\*(?:[^*]|\*(?!\/))*\*\/|\\(?:\r\n|[\s\S]))*/im,
          lookbehind: !0,
          greedy: !0,
          alias: 'property',
          inside: {
            string: [
              {
                pattern: /^(#\s*include\s*)<[^>]+>/,
                lookbehind: !0
              },
              d.languages.c.string
            ],
            comment: d.languages.c.comment,
            'macro-name': [
              {
                pattern: /(^#\s*define\s+)\w+\b(?!\()/i,
                lookbehind: !0
              },
              {
                pattern: /(^#\s*define\s+)\w+\b(?=\()/i,
                lookbehind: !0,
                alias: 'function'
              }
            ],
            directive: {
              pattern: /^(#\s*)[a-z]+/,
              lookbehind: !0,
              alias: 'keyword'
            },
            'directive-hash': /^#/,
            punctuation: /##|\\(?=[\r\n])/,
            expression: {
              pattern: /\S[\s\S]*/,
              inside: d.languages.c
            }
          }
        },
        constant: /\b(?:__FILE__|__LINE__|__DATE__|__TIME__|__TIMESTAMP__|__func__|EOF|NULL|SEEK_CUR|SEEK_END|SEEK_SET|stdin|stdout|stderr)\b/
      }),
      delete d.languages.c.boolean,
      function (e) {
        function t(e, t) {
          return e.replace(/<<(\d+)>>/g, (function (e, n) {
            return '(?:' + t[ + n] + ')'
          }))
        }
        function n(e, n, a) {
          return RegExp(t(e, n), a || '')
        }
        function a(e, t) {
          for (var n = 0; n < t; n++) e = e.replace(/<<self>>/g, (function () {
            return '(?:' + e + ')'
          }));
          return e.replace(/<<self>>/g, '[^\\s\\S]')
        }
        var r = 'bool byte char decimal double dynamic float int long object sbyte short string uint ulong ushort var void',
        i = 'class enum interface record struct',
        o = 'add alias and ascending async await by descending from(?=\\s*(?:\\w|$)) get global group into init(?=\\s*;) join let nameof not notnull on or orderby partial remove select set unmanaged value when where with(?=\\s*{)',
        s = 'abstract as base break case catch checked const continue default delegate do else event explicit extern finally fixed for foreach goto if implicit in internal is lock namespace new null operator out override params private protected public readonly ref return sealed sizeof stackalloc static switch this throw try typeof unchecked unsafe using virtual volatile while yield';
        function l(e) {
          return '\\b(?:' + e.trim().replace(/ /g, '|') + ')\\b'
        }
        var d = l(i),
        u = RegExp(l(r + ' ' + i + ' ' + o + ' ' + s)),
        c = l(i + ' ' + o + ' ' + s),
        p = l(r + ' ' + i + ' ' + s),
        g = a('<(?:[^<>;=+\\-*/%&|^]|<<self>>)*>', 2),
        b = a('\\((?:[^()]|<<self>>)*\\)', 2),
        m = '@?\\b[A-Za-z_]\\w*\\b',
        f = t('<<0>>(?:\\s*<<1>>)?', [
          m,
          g
        ]),
        h = t('(?!<<0>>)<<1>>(?:\\s*\\.\\s*<<1>>)*', [
          c,
          f
        ]),
        E = '\\[\\s*(?:,\\s*)*\\]',
        _ = t('<<0>>(?:\\s*(?:\\?\\s*)?<<1>>)*(?:\\s*\\?)?', [
          h,
          E
        ]),
        S = t('(?:<<0>>|<<1>>)(?:\\s*(?:\\?\\s*)?<<2>>)*(?:\\s*\\?)?', [
          t('\\(<<0>>+(?:,<<0>>+)+\\)', [
            t('[^,()<>[\\];=+\\-*/%&|^]|<<0>>|<<1>>|<<2>>', [
              g,
              b,
              E
            ])
          ]),
          h,
          E
        ]),
        y = {
          keyword: u,
          punctuation: /[<>()?,.:[\]]/
        },
        v = '\'(?:[^\r\n\'\\\\]|\\\\.|\\\\[Uux][\\da-fA-F]{1,8})\'',
        A = '"(?:\\\\.|[^\\\\"\r\n])*"';
        e.languages.csharp = e.languages.extend('clike', {
          string: [
            {
              pattern: n('(^|[^$\\\\])<<0>>', [
                '@"(?:""|\\\\[^]|[^\\\\"])*"(?!")'
              ]),
              lookbehind: !0,
              greedy: !0
            },
            {
              pattern: n('(^|[^@$\\\\])<<0>>', [
                A
              ]),
              lookbehind: !0,
              greedy: !0
            },
            {
              pattern: RegExp(v),
              greedy: !0,
              alias: 'character'
            }
          ],
          'class-name': [
            {
              pattern: n('(\\busing\\s+static\\s+)<<0>>(?=\\s*;)', [
                h
              ]),
              lookbehind: !0,
              inside: y
            },
            {
              pattern: n('(\\busing\\s+<<0>>\\s*=\\s*)<<1>>(?=\\s*;)', [
                m,
                S
              ]),
              lookbehind: !0,
              inside: y
            },
            {
              pattern: n('(\\busing\\s+)<<0>>(?=\\s*=)', [
                m
              ]),
              lookbehind: !0
            },
            {
              pattern: n('(\\b<<0>>\\s+)<<1>>', [
                d,
                f
              ]),
              lookbehind: !0,
              inside: y
            },
            {
              pattern: n('(\\bcatch\\s*\\(\\s*)<<0>>', [
                h
              ]),
              lookbehind: !0,
              inside: y
            },
            {
              pattern: n('(\\bwhere\\s+)<<0>>', [
                m
              ]),
              lookbehind: !0
            },
            {
              pattern: n('(\\b(?:is(?:\\s+not)?|as)\\s+)<<0>>', [
                _
              ]),
              lookbehind: !0,
              inside: y
            },
            {
              pattern: n('\\b<<0>>(?=\\s+(?!<<1>>|with\\s*\\{)<<2>>(?:\\s*[=,;:{)\\]]|\\s+(?:in|when)\\b))', [
                S,
                p,
                m
              ]),
              inside: y
            }
          ],
          keyword: u,
          number: /(?:\b0(?:x[\da-f_]*[\da-f]|b[01_]*[01])|(?:\B\.\d+(?:_+\d+)*|\b\d+(?:_+\d+)*(?:\.\d+(?:_+\d+)*)?)(?:e[-+]?\d+(?:_+\d+)*)?)(?:ul|lu|[dflmu])?\b/i,
          operator: />>=?|<<=?|[-=]>|([-+&|])\1|~|\?\?=?|[-+*/%&|^!=<>]=?/,
          punctuation: /\?\.?|::|[{}[\];(),.:]/
        }),
        e.languages.insertBefore('csharp', 'number', {
          range: {
            pattern: /\.\./,
            alias: 'operator'
          }
        }),
        e.languages.insertBefore('csharp', 'punctuation', {
          'named-parameter': {
            pattern: n('([(,]\\s*)<<0>>(?=\\s*:)', [
              m
            ]),
            lookbehind: !0,
            alias: 'punctuation'
          }
        }),
        e.languages.insertBefore('csharp', 'class-name', {
          namespace: {
            pattern: n('(\\b(?:namespace|using)\\s+)<<0>>(?:\\s*\\.\\s*<<0>>)*(?=\\s*[;{])', [
              m
            ]),
            lookbehind: !0,
            inside: {
              punctuation: /\./
            }
          },
          'type-expression': {
            pattern: n('(\\b(?:default|typeof|sizeof)\\s*\\(\\s*(?!\\s))(?:[^()\\s]|\\s(?!\\s)|<<0>>)*(?=\\s*\\))', [
              b
            ]),
            lookbehind: !0,
            alias: 'class-name',
            inside: y
          },
          'return-type': {
            pattern: n('<<0>>(?=\\s+(?:<<1>>\\s*(?:=>|[({]|\\.\\s*this\\s*\\[)|this\\s*\\[))', [
              S,
              h
            ]),
            inside: y,
            alias: 'class-name'
          },
          'constructor-invocation': {
            pattern: n('(\\bnew\\s+)<<0>>(?=\\s*[[({])', [
              S
            ]),
            lookbehind: !0,
            inside: y,
            alias: 'class-name'
          },
          'generic-method': {
            pattern: n('<<0>>\\s*<<1>>(?=\\s*\\()', [
              m,
              g
            ]),
            inside: {
              function : n('^<<0>>', [
                m
              ]),
              generic: {
                pattern: RegExp(g),
                alias: 'class-name',
                inside: y
              }
            }
          },
          'type-list': {
            pattern: n('\\b((?:<<0>>\\s+<<1>>|record\\s+<<1>>\\s*<<5>>|where\\s+<<2>>)\\s*:\\s*)(?:<<3>>|<<4>>|<<1>>\\s*<<5>>|<<6>>)(?:\\s*,\\s*(?:<<3>>|<<4>>|<<6>>))*(?=\\s*(?:where|[{;]|=>|$))', [
              d,
              f,
              m,
              S,
              u.source,
              b,
              '\\bnew\\s*\\(\\s*\\)'
            ]),
            lookbehind: !0,
            inside: {
              'record-arguments': {
                pattern: n('(^(?!new\\s*\\()<<0>>\\s*)<<1>>', [
                  f,
                  b
                ]),
                lookbehind: !0,
                greedy: !0,
                inside: e.languages.csharp
              },
              keyword: u,
              'class-name': {
                pattern: RegExp(S),
                greedy: !0,
                inside: y
              },
              punctuation: /[,()]/
            }
          },
          preprocessor: {
            pattern: /(^[\t ]*)#.*/m,
            lookbehind: !0,
            alias: 'property',
            inside: {
              directive: {
                pattern: /(#)\b(?:define|elif|else|endif|endregion|error|if|line|nullable|pragma|region|undef|warning)\b/,
                lookbehind: !0,
                alias: 'keyword'
              }
            }
          }
        });
        var w = A + '|' + v,
        T = t('/(?![*/])|//[^\r\n]*[\r\n]|/\\*(?:[^*]|\\*(?!/))*\\*/|<<0>>', [
          w
        ]),
        k = a(t('[^"\'/()]|<<0>>|\\(<<self>>*\\)', [
          T
        ]), 2),
        I = '\\b(?:assembly|event|field|method|module|param|property|return|type)\\b',
        R = t('<<0>>(?:\\s*\\(<<1>>*\\))?', [
          h,
          k
        ]);
        e.languages.insertBefore('csharp', 'class-name', {
          attribute: {
            pattern: n('((?:^|[^\\s\\w>)?])\\s*\\[\\s*)(?:<<0>>\\s*:\\s*)?<<1>>(?:\\s*,\\s*<<1>>)*(?=\\s*\\])', [
              I,
              R
            ]),
            lookbehind: !0,
            greedy: !0,
            inside: {
              target: {
                pattern: n('^<<0>>(?=\\s*:)', [
                  I
                ]),
                alias: 'keyword'
              },
              'attribute-arguments': {
                pattern: n('\\(<<0>>*\\)', [
                  k
                ]),
                inside: e.languages.csharp
              },
              'class-name': {
                pattern: RegExp(h),
                inside: {
                  punctuation: /\./
                }
              },
              punctuation: /[:,]/
            }
          }
        });
        var O = ':[^}\r\n]+',
        N = a(t('[^"\'/()]|<<0>>|\\(<<self>>*\\)', [
          T
        ]), 2),
        C = t('\\{(?!\\{)(?:(?![}:])<<0>>)*<<1>>?\\}', [
          N,
          O
        ]),
        L = a(t('[^"\'/()]|/(?!\\*)|/\\*(?:[^*]|\\*(?!/))*\\*/|<<0>>|\\(<<self>>*\\)', [
          w
        ]), 2),
        D = t('\\{(?!\\{)(?:(?![}:])<<0>>)*<<1>>?\\}', [
          L,
          O
        ]);
        function x(t, a) {
          return {
            interpolation: {
              pattern: n('((?:^|[^{])(?:\\{\\{)*)<<0>>', [
                t
              ]),
              lookbehind: !0,
              inside: {
                'format-string': {
                  pattern: n('(^\\{(?:(?![}:])<<0>>)*)<<1>>(?=\\}$)', [
                    a,
                    O
                  ]),
                  lookbehind: !0,
                  inside: {
                    punctuation: /^:/
                  }
                },
                punctuation: /^\{|\}$/,
                expression: {
                  pattern: /[\s\S]+/,
                  alias: 'language-csharp',
                  inside: e.languages.csharp
                }
              }
            },
            string: /[\s\S]+/
          }
        }
        e.languages.insertBefore('csharp', 'string', {
          'interpolation-string': [
            {
              pattern: n('(^|[^\\\\])(?:\\$@|@\\$)"(?:""|\\\\[^]|\\{\\{|<<0>>|[^\\\\{"])*"', [
                C
              ]),
              lookbehind: !0,
              greedy: !0,
              inside: x(C, N)
            },
            {
              pattern: n('(^|[^@\\\\])\\$"(?:\\\\.|\\{\\{|<<0>>|[^\\\\"{])*"', [
                D
              ]),
              lookbehind: !0,
              greedy: !0,
              inside: x(D, L)
            }
          ]
        })
      }(d),
      d.languages.dotnet = d.languages.cs = d.languages.csharp,
      a = d,
      r = /\b(?:alignas|alignof|asm|auto|bool|break|case|catch|char|char8_t|char16_t|char32_t|class|compl|concept|const|consteval|constexpr|constinit|const_cast|continue|co_await|co_return|co_yield|decltype|default|delete|do|double|dynamic_cast|else|enum|explicit|export|extern|final|float|for|friend|goto|if|import|inline|int|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|long|module|mutable|namespace|new|noexcept|nullptr|operator|override|private|protected|public|register|reinterpret_cast|requires|return|short|signed|sizeof|static|static_assert|static_cast|struct|switch|template|this|thread_local|throw|try|typedef|typeid|typename|union|unsigned|using|virtual|void|volatile|wchar_t|while)\b/,
      i = '\\b(?!<keyword>)\\w+(?:\\s*\\.\\s*\\w+)*\\b'.replace(/<keyword>/g, (function () {
        return r.source
      })),
      a.languages.cpp = a.languages.extend('c', {
        'class-name': [
          {
            pattern: RegExp('(\\b(?:class|concept|enum|struct|typename)\\s+)(?!<keyword>)\\w+'.replace(/<keyword>/g, (function () {
              return r.source
            }))),
            lookbehind: !0
          },
          /\b[A-Z]\w*(?=\s*::\s*\w+\s*\()/,
          /\b[A-Z_]\w*(?=\s*::\s*~\w+\s*\()/i,
          /\b\w+(?=\s*<(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*>\s*::\s*\w+\s*\()/
        ],
        keyword: r,
        number: {
          pattern: /(?:\b0b[01']+|\b0x(?:[\da-f']+(?:\.[\da-f']*)?|\.[\da-f']+)(?:p[+-]?[\d']+)?|(?:\b[\d']+(?:\.[\d']*)?|\B\.[\d']+)(?:e[+-]?[\d']+)?)[ful]{0,4}/i,
          greedy: !0
        },
        operator: />>=?|<<=?|->|--|\+\+|&&|\|\||[?:~]|<=>|[-+*/%&|^!=<>]=?|\b(?:and|and_eq|bitand|bitor|not|not_eq|or|or_eq|xor|xor_eq)\b/,
        boolean: /\b(?:true|false)\b/
      }),
      a.languages.insertBefore('cpp', 'string', {
        module: {
          pattern: RegExp('(\\b(?:module|import)\\s+)(?:"(?:\\\\(?:\r\n|[^])|[^"\\\\\r\n])*"|<[^<>\r\n]*>|' + '<mod-name>(?:\\s*:\\s*<mod-name>)?|:\\s*<mod-name>'.replace(/<mod-name>/g, (function () {
            return i
          })) + ')'),
          lookbehind: !0,
          greedy: !0,
          inside: {
            string: /^[<"][\s\S]+/,
            operator: /:/,
            punctuation: /\./
          }
        },
        'raw-string': {
          pattern: /R"([^()\\ ]{0,16})\([\s\S]*?\)\1"/,
          alias: 'string',
          greedy: !0
        }
      }),
      a.languages.insertBefore('cpp', 'keyword', {
        'generic-function': {
          pattern: /\b[a-z_]\w*\s*<(?:[^<>]|<(?:[^<>])*>)*>(?=\s*\()/i,
          inside: {
            function : /^\w+/,
            generic: {
              pattern: /<[\s\S]+/,
              alias: 'class-name',
              inside: a.languages.cpp
            }
          }
        }
      }),
      a.languages.insertBefore('cpp', 'operator', {
        'double-colon': {
          pattern: /::/,
          alias: 'punctuation'
        }
      }),
      a.languages.insertBefore('cpp', 'class-name', {
        'base-clause': {
          pattern: /(\b(?:class|struct)\s+\w+\s*:\s*)[^;{}"'\s]+(?:\s+[^;{}"'\s]+)*(?=\s*[;{])/,
          lookbehind: !0,
          greedy: !0,
          inside: a.languages.extend('cpp', {
          })
        }
      }),
      a.languages.insertBefore('inside', 'double-colon', {
        'class-name': /\b[a-z_]\w*\b(?!\s*::)/i
      }, a.languages.cpp['base-clause']),
      d.languages.cmake = {
        comment: /#.*/,
        string: {
          pattern: /"(?:[^\\"]|\\.)*"/,
          greedy: !0,
          inside: {
            interpolation: {
              pattern: /\$\{(?:[^{}$]|\$\{[^{}$]*\})*\}/,
              inside: {
                punctuation: /\$\{|\}/,
                variable: /\w+/
              }
            }
          }
        },
        variable: /\b(?:CMAKE_\w+|\w+_(?:VERSION(?:_MAJOR|_MINOR|_PATCH|_TWEAK)?|(?:BINARY|SOURCE)_DIR|DESCRIPTION|HOMEPAGE_URL|ROOT)|(?:ANDROID|APPLE|BORLAND|BUILD_SHARED_LIBS|CACHE|CPACK_(?:ABSOLUTE_DESTINATION_FILES|COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY|ERROR_ON_ABSOLUTE_INSTALL_DESTINATION|INCLUDE_TOPLEVEL_DIRECTORY|INSTALL_DEFAULT_DIRECTORY_PERMISSIONS|INSTALL_SCRIPT|PACKAGING_INSTALL_PREFIX|SET_DESTDIR|WARN_ON_ABSOLUTE_INSTALL_DESTINATION)|CTEST_(?:BINARY_DIRECTORY|BUILD_COMMAND|BUILD_NAME|BZR_COMMAND|BZR_UPDATE_OPTIONS|CHANGE_ID|CHECKOUT_COMMAND|CONFIGURATION_TYPE|CONFIGURE_COMMAND|COVERAGE_COMMAND|COVERAGE_EXTRA_FLAGS|CURL_OPTIONS|CUSTOM_(?:COVERAGE_EXCLUDE|ERROR_EXCEPTION|ERROR_MATCH|ERROR_POST_CONTEXT|ERROR_PRE_CONTEXT|MAXIMUM_FAILED_TEST_OUTPUT_SIZE|MAXIMUM_NUMBER_OF_(?:ERRORS|WARNINGS)|MAXIMUM_PASSED_TEST_OUTPUT_SIZE|MEMCHECK_IGNORE|POST_MEMCHECK|POST_TEST|PRE_MEMCHECK|PRE_TEST|TESTS_IGNORE|WARNING_EXCEPTION|WARNING_MATCH)|CVS_CHECKOUT|CVS_COMMAND|CVS_UPDATE_OPTIONS|DROP_LOCATION|DROP_METHOD|DROP_SITE|DROP_SITE_CDASH|DROP_SITE_PASSWORD|DROP_SITE_USER|EXTRA_COVERAGE_GLOB|GIT_COMMAND|GIT_INIT_SUBMODULES|GIT_UPDATE_CUSTOM|GIT_UPDATE_OPTIONS|HG_COMMAND|HG_UPDATE_OPTIONS|LABELS_FOR_SUBPROJECTS|MEMORYCHECK_(?:COMMAND|COMMAND_OPTIONS|SANITIZER_OPTIONS|SUPPRESSIONS_FILE|TYPE)|NIGHTLY_START_TIME|P4_CLIENT|P4_COMMAND|P4_OPTIONS|P4_UPDATE_OPTIONS|RUN_CURRENT_SCRIPT|SCP_COMMAND|SITE|SOURCE_DIRECTORY|SUBMIT_URL|SVN_COMMAND|SVN_OPTIONS|SVN_UPDATE_OPTIONS|TEST_LOAD|TEST_TIMEOUT|TRIGGER_SITE|UPDATE_COMMAND|UPDATE_OPTIONS|UPDATE_VERSION_ONLY|USE_LAUNCHERS)|CYGWIN|ENV|EXECUTABLE_OUTPUT_PATH|GHS-MULTI|IOS|LIBRARY_OUTPUT_PATH|MINGW|MSVC(?:10|11|12|14|60|70|71|80|90|_IDE|_TOOLSET_VERSION|_VERSION)?|MSYS|PROJECT_(?:BINARY_DIR|DESCRIPTION|HOMEPAGE_URL|NAME|SOURCE_DIR|VERSION|VERSION_(?:MAJOR|MINOR|PATCH|TWEAK))|UNIX|WIN32|WINCE|WINDOWS_PHONE|WINDOWS_STORE|XCODE|XCODE_VERSION))\b/,
        property: /\b(?:cxx_\w+|(?:ARCHIVE_OUTPUT_(?:DIRECTORY|NAME)|COMPILE_DEFINITIONS|COMPILE_PDB_NAME|COMPILE_PDB_OUTPUT_DIRECTORY|EXCLUDE_FROM_DEFAULT_BUILD|IMPORTED_(?:IMPLIB|LIBNAME|LINK_DEPENDENT_LIBRARIES|LINK_INTERFACE_LANGUAGES|LINK_INTERFACE_LIBRARIES|LINK_INTERFACE_MULTIPLICITY|LOCATION|NO_SONAME|OBJECTS|SONAME)|INTERPROCEDURAL_OPTIMIZATION|LIBRARY_OUTPUT_DIRECTORY|LIBRARY_OUTPUT_NAME|LINK_FLAGS|LINK_INTERFACE_LIBRARIES|LINK_INTERFACE_MULTIPLICITY|LOCATION|MAP_IMPORTED_CONFIG|OSX_ARCHITECTURES|OUTPUT_NAME|PDB_NAME|PDB_OUTPUT_DIRECTORY|RUNTIME_OUTPUT_DIRECTORY|RUNTIME_OUTPUT_NAME|STATIC_LIBRARY_FLAGS|VS_CSHARP|VS_DOTNET_REFERENCEPROP|VS_DOTNET_REFERENCE|VS_GLOBAL_SECTION_POST|VS_GLOBAL_SECTION_PRE|VS_GLOBAL|XCODE_ATTRIBUTE)_\w+|\w+_(?:CLANG_TIDY|COMPILER_LAUNCHER|CPPCHECK|CPPLINT|INCLUDE_WHAT_YOU_USE|OUTPUT_NAME|POSTFIX|VISIBILITY_PRESET)|ABSTRACT|ADDITIONAL_MAKE_CLEAN_FILES|ADVANCED|ALIASED_TARGET|ALLOW_DUPLICATE_CUSTOM_TARGETS|ANDROID_(?:ANT_ADDITIONAL_OPTIONS|API|API_MIN|ARCH|ASSETS_DIRECTORIES|GUI|JAR_DEPENDENCIES|NATIVE_LIB_DEPENDENCIES|NATIVE_LIB_DIRECTORIES|PROCESS_MAX|PROGUARD|PROGUARD_CONFIG_PATH|SECURE_PROPS_PATH|SKIP_ANT_STEP|STL_TYPE)|ARCHIVE_OUTPUT_DIRECTORY|ATTACHED_FILES|ATTACHED_FILES_ON_FAIL|AUTOGEN_(?:BUILD_DIR|ORIGIN_DEPENDS|PARALLEL|SOURCE_GROUP|TARGETS_FOLDER|TARGET_DEPENDS)|AUTOMOC|AUTOMOC_(?:COMPILER_PREDEFINES|DEPEND_FILTERS|EXECUTABLE|MACRO_NAMES|MOC_OPTIONS|SOURCE_GROUP|TARGETS_FOLDER)|AUTORCC|AUTORCC_EXECUTABLE|AUTORCC_OPTIONS|AUTORCC_SOURCE_GROUP|AUTOUIC|AUTOUIC_EXECUTABLE|AUTOUIC_OPTIONS|AUTOUIC_SEARCH_PATHS|BINARY_DIR|BUILDSYSTEM_TARGETS|BUILD_RPATH|BUILD_RPATH_USE_ORIGIN|BUILD_WITH_INSTALL_NAME_DIR|BUILD_WITH_INSTALL_RPATH|BUNDLE|BUNDLE_EXTENSION|CACHE_VARIABLES|CLEAN_NO_CUSTOM|COMMON_LANGUAGE_RUNTIME|COMPATIBLE_INTERFACE_(?:BOOL|NUMBER_MAX|NUMBER_MIN|STRING)|COMPILE_(?:DEFINITIONS|FEATURES|FLAGS|OPTIONS|PDB_NAME|PDB_OUTPUT_DIRECTORY)|COST|CPACK_DESKTOP_SHORTCUTS|CPACK_NEVER_OVERWRITE|CPACK_PERMANENT|CPACK_STARTUP_SHORTCUTS|CPACK_START_MENU_SHORTCUTS|CPACK_WIX_ACL|CROSSCOMPILING_EMULATOR|CUDA_EXTENSIONS|CUDA_PTX_COMPILATION|CUDA_RESOLVE_DEVICE_SYMBOLS|CUDA_SEPARABLE_COMPILATION|CUDA_STANDARD|CUDA_STANDARD_REQUIRED|CXX_EXTENSIONS|CXX_STANDARD|CXX_STANDARD_REQUIRED|C_EXTENSIONS|C_STANDARD|C_STANDARD_REQUIRED|DEBUG_CONFIGURATIONS|DEFINE_SYMBOL|DEFINITIONS|DEPENDS|DEPLOYMENT_ADDITIONAL_FILES|DEPLOYMENT_REMOTE_DIRECTORY|DISABLED|DISABLED_FEATURES|ECLIPSE_EXTRA_CPROJECT_CONTENTS|ECLIPSE_EXTRA_NATURES|ENABLED_FEATURES|ENABLED_LANGUAGES|ENABLE_EXPORTS|ENVIRONMENT|EXCLUDE_FROM_ALL|EXCLUDE_FROM_DEFAULT_BUILD|EXPORT_NAME|EXPORT_PROPERTIES|EXTERNAL_OBJECT|EchoString|FAIL_REGULAR_EXPRESSION|FIND_LIBRARY_USE_LIB32_PATHS|FIND_LIBRARY_USE_LIB64_PATHS|FIND_LIBRARY_USE_LIBX32_PATHS|FIND_LIBRARY_USE_OPENBSD_VERSIONING|FIXTURES_CLEANUP|FIXTURES_REQUIRED|FIXTURES_SETUP|FOLDER|FRAMEWORK|Fortran_FORMAT|Fortran_MODULE_DIRECTORY|GENERATED|GENERATOR_FILE_NAME|GENERATOR_IS_MULTI_CONFIG|GHS_INTEGRITY_APP|GHS_NO_SOURCE_GROUP_FILE|GLOBAL_DEPENDS_DEBUG_MODE|GLOBAL_DEPENDS_NO_CYCLES|GNUtoMS|HAS_CXX|HEADER_FILE_ONLY|HELPSTRING|IMPLICIT_DEPENDS_INCLUDE_TRANSFORM|IMPORTED|IMPORTED_(?:COMMON_LANGUAGE_RUNTIME|CONFIGURATIONS|GLOBAL|IMPLIB|LIBNAME|LINK_DEPENDENT_LIBRARIES|LINK_INTERFACE_(?:LANGUAGES|LIBRARIES|MULTIPLICITY)|LOCATION|NO_SONAME|OBJECTS|SONAME)|IMPORT_PREFIX|IMPORT_SUFFIX|INCLUDE_DIRECTORIES|INCLUDE_REGULAR_EXPRESSION|INSTALL_NAME_DIR|INSTALL_RPATH|INSTALL_RPATH_USE_LINK_PATH|INTERFACE_(?:AUTOUIC_OPTIONS|COMPILE_DEFINITIONS|COMPILE_FEATURES|COMPILE_OPTIONS|INCLUDE_DIRECTORIES|LINK_DEPENDS|LINK_DIRECTORIES|LINK_LIBRARIES|LINK_OPTIONS|POSITION_INDEPENDENT_CODE|SOURCES|SYSTEM_INCLUDE_DIRECTORIES)|INTERPROCEDURAL_OPTIMIZATION|IN_TRY_COMPILE|IOS_INSTALL_COMBINED|JOB_POOLS|JOB_POOL_COMPILE|JOB_POOL_LINK|KEEP_EXTENSION|LABELS|LANGUAGE|LIBRARY_OUTPUT_DIRECTORY|LINKER_LANGUAGE|LINK_(?:DEPENDS|DEPENDS_NO_SHARED|DIRECTORIES|FLAGS|INTERFACE_LIBRARIES|INTERFACE_MULTIPLICITY|LIBRARIES|OPTIONS|SEARCH_END_STATIC|SEARCH_START_STATIC|WHAT_YOU_USE)|LISTFILE_STACK|LOCATION|MACOSX_BUNDLE|MACOSX_BUNDLE_INFO_PLIST|MACOSX_FRAMEWORK_INFO_PLIST|MACOSX_PACKAGE_LOCATION|MACOSX_RPATH|MACROS|MANUALLY_ADDED_DEPENDENCIES|MEASUREMENT|MODIFIED|NAME|NO_SONAME|NO_SYSTEM_FROM_IMPORTED|OBJECT_DEPENDS|OBJECT_OUTPUTS|OSX_ARCHITECTURES|OUTPUT_NAME|PACKAGES_FOUND|PACKAGES_NOT_FOUND|PARENT_DIRECTORY|PASS_REGULAR_EXPRESSION|PDB_NAME|PDB_OUTPUT_DIRECTORY|POSITION_INDEPENDENT_CODE|POST_INSTALL_SCRIPT|PREDEFINED_TARGETS_FOLDER|PREFIX|PRE_INSTALL_SCRIPT|PRIVATE_HEADER|PROCESSORS|PROCESSOR_AFFINITY|PROJECT_LABEL|PUBLIC_HEADER|REPORT_UNDEFINED_PROPERTIES|REQUIRED_FILES|RESOURCE|RESOURCE_LOCK|RULE_LAUNCH_COMPILE|RULE_LAUNCH_CUSTOM|RULE_LAUNCH_LINK|RULE_MESSAGES|RUNTIME_OUTPUT_DIRECTORY|RUN_SERIAL|SKIP_AUTOGEN|SKIP_AUTOMOC|SKIP_AUTORCC|SKIP_AUTOUIC|SKIP_BUILD_RPATH|SKIP_RETURN_CODE|SOURCES|SOURCE_DIR|SOVERSION|STATIC_LIBRARY_FLAGS|STATIC_LIBRARY_OPTIONS|STRINGS|SUBDIRECTORIES|SUFFIX|SYMBOLIC|TARGET_ARCHIVES_MAY_BE_SHARED_LIBS|TARGET_MESSAGES|TARGET_SUPPORTS_SHARED_LIBS|TESTS|TEST_INCLUDE_FILE|TEST_INCLUDE_FILES|TIMEOUT|TIMEOUT_AFTER_MATCH|TYPE|USE_FOLDERS|VALUE|VARIABLES|VERSION|VISIBILITY_INLINES_HIDDEN|VS_(?:CONFIGURATION_TYPE|COPY_TO_OUT_DIR|DEBUGGER_(?:COMMAND|COMMAND_ARGUMENTS|ENVIRONMENT|WORKING_DIRECTORY)|DEPLOYMENT_CONTENT|DEPLOYMENT_LOCATION|DOTNET_REFERENCES|DOTNET_REFERENCES_COPY_LOCAL|GLOBAL_KEYWORD|GLOBAL_PROJECT_TYPES|GLOBAL_ROOTNAMESPACE|INCLUDE_IN_VSIX|IOT_STARTUP_TASK|KEYWORD|RESOURCE_GENERATOR|SCC_AUXPATH|SCC_LOCALPATH|SCC_PROJECTNAME|SCC_PROVIDER|SDK_REFERENCES|SHADER_(?:DISABLE_OPTIMIZATIONS|ENABLE_DEBUG|ENTRYPOINT|FLAGS|MODEL|OBJECT_FILE_NAME|OUTPUT_HEADER_FILE|TYPE|VARIABLE_NAME)|STARTUP_PROJECT|TOOL_OVERRIDE|USER_PROPS|WINRT_COMPONENT|WINRT_EXTENSIONS|WINRT_REFERENCES|XAML_TYPE)|WILL_FAIL|WIN32_EXECUTABLE|WINDOWS_EXPORT_ALL_SYMBOLS|WORKING_DIRECTORY|WRAP_EXCLUDE|XCODE_(?:EMIT_EFFECTIVE_PLATFORM_NAME|EXPLICIT_FILE_TYPE|FILE_ATTRIBUTES|LAST_KNOWN_FILE_TYPE|PRODUCT_TYPE|SCHEME_(?:ADDRESS_SANITIZER|ADDRESS_SANITIZER_USE_AFTER_RETURN|ARGUMENTS|DISABLE_MAIN_THREAD_CHECKER|DYNAMIC_LIBRARY_LOADS|DYNAMIC_LINKER_API_USAGE|ENVIRONMENT|EXECUTABLE|GUARD_MALLOC|MAIN_THREAD_CHECKER_STOP|MALLOC_GUARD_EDGES|MALLOC_SCRIBBLE|MALLOC_STACK|THREAD_SANITIZER(?:_STOP)?|UNDEFINED_BEHAVIOUR_SANITIZER(?:_STOP)?|ZOMBIE_OBJECTS))|XCTEST)\b/,
        keyword: /\b(?:add_compile_definitions|add_compile_options|add_custom_command|add_custom_target|add_definitions|add_dependencies|add_executable|add_library|add_link_options|add_subdirectory|add_test|aux_source_directory|break|build_command|build_name|cmake_host_system_information|cmake_minimum_required|cmake_parse_arguments|cmake_policy|configure_file|continue|create_test_sourcelist|ctest_build|ctest_configure|ctest_coverage|ctest_empty_binary_directory|ctest_memcheck|ctest_read_custom_files|ctest_run_script|ctest_sleep|ctest_start|ctest_submit|ctest_test|ctest_update|ctest_upload|define_property|else|elseif|enable_language|enable_testing|endforeach|endfunction|endif|endmacro|endwhile|exec_program|execute_process|export|export_library_dependencies|file|find_file|find_library|find_package|find_path|find_program|fltk_wrap_ui|foreach|function|get_cmake_property|get_directory_property|get_filename_component|get_property|get_source_file_property|get_target_property|get_test_property|if|include|include_directories|include_external_msproject|include_guard|include_regular_expression|install|install_files|install_programs|install_targets|link_directories|link_libraries|list|load_cache|load_command|macro|make_directory|mark_as_advanced|math|message|option|output_required_files|project|qt_wrap_cpp|qt_wrap_ui|remove|remove_definitions|return|separate_arguments|set|set_directory_properties|set_property|set_source_files_properties|set_target_properties|set_tests_properties|site_name|source_group|string|subdir_depends|subdirs|target_compile_definitions|target_compile_features|target_compile_options|target_include_directories|target_link_directories|target_link_libraries|target_link_options|target_sources|try_compile|try_run|unset|use_mangled_mesa|utility_source|variable_requires|variable_watch|while|write_file)(?=\s*\()\b/,
        boolean: /\b(?:ON|OFF|TRUE|FALSE)\b/,
        namespace: /\b(?:PROPERTIES|SHARED|PRIVATE|STATIC|PUBLIC|INTERFACE|TARGET_OBJECTS)\b/,
        operator: /\b(?:NOT|AND|OR|MATCHES|LESS|GREATER|EQUAL|STRLESS|STRGREATER|STREQUAL|VERSION_LESS|VERSION_EQUAL|VERSION_GREATER|DEFINED)\b/,
        inserted: {
          pattern: /\b\w+::\w+\b/,
          alias: 'class-name'
        },
        number: /\b\d+(?:\.\d+)*\b/,
        function : /\b[a-z_]\w*(?=\s*\()\b/i,
        punctuation: /[()>}]|\$[<{]/
      },
      function (e) {
        var t = /#(?!\{).+/,
        n = {
          pattern: /#\{[^}]+\}/,
          alias: 'variable'
        };
        e.languages.coffeescript = e.languages.extend('javascript', {
          comment: t,
          string: [
            {
              pattern: /'(?:\\[\s\S]|[^\\'])*'/,
              greedy: !0
            },
            {
              pattern: /"(?:\\[\s\S]|[^\\"])*"/,
              greedy: !0,
              inside: {
                interpolation: n
              }
            }
          ],
          keyword: /\b(?:and|break|by|catch|class|continue|debugger|delete|do|each|else|extend|extends|false|finally|for|if|in|instanceof|is|isnt|let|loop|namespace|new|no|not|null|of|off|on|or|own|return|super|switch|then|this|throw|true|try|typeof|undefined|unless|until|when|while|window|with|yes|yield)\b/,
          'class-member': {
            pattern: /@(?!\d)\w+/,
            alias: 'variable'
          }
        }),
        e.languages.insertBefore('coffeescript', 'comment', {
          'multiline-comment': {
            pattern: /###[\s\S]+?###/,
            alias: 'comment'
          },
          'block-regex': {
            pattern: /\/{3}[\s\S]*?\/{3}/,
            alias: 'regex',
            inside: {
              comment: t,
              interpolation: n
            }
          }
        }),
        e.languages.insertBefore('coffeescript', 'string', {
          'inline-javascript': {
            pattern: /`(?:\\[\s\S]|[^\\`])*`/,
            inside: {
              delimiter: {
                pattern: /^`|`$/,
                alias: 'punctuation'
              },
              script: {
                pattern: /[\s\S]+/,
                alias: 'language-javascript',
                inside: e.languages.javascript
              }
            }
          },
          'multiline-string': [
            {
              pattern: /'''[\s\S]*?'''/,
              greedy: !0,
              alias: 'string'
            },
            {
              pattern: /"""[\s\S]*?"""/,
              greedy: !0,
              alias: 'string',
              inside: {
                interpolation: n
              }
            }
          ]
        }),
        e.languages.insertBefore('coffeescript', 'keyword', {
          property: /(?!\d)\w+(?=\s*:(?!:))/
        }),
        delete e.languages.coffeescript['template-string'],
        e.languages.coffee = e.languages.coffeescript
      }(d),
      d.languages.csp = {
        directive: {
          pattern: /(^|[^-\da-z])(?:base-uri|block-all-mixed-content|(?:child|connect|default|font|frame|img|manifest|media|object|prefetch|script|style|worker)-src|disown-opener|form-action|frame-(?:ancestors|options)|input-protection(?:-(?:clip|selectors))?|navigate-to|plugin-types|policy-uri|referrer|reflected-xss|report-(?:to|uri)|require-sri-for|sandbox|(?:script|style)-src-(?:attr|elem)|upgrade-insecure-requests)(?=[^-\da-z]|$)/i,
          lookbehind: !0,
          alias: 'keyword'
        },
        safe: {
          pattern: /'(?:deny|none|report-sample|self|strict-dynamic|top-only|(?:nonce|sha(?:256|384|512))-[-+/\w=]+)'/i,
          alias: 'selector'
        },
        unsafe: {
          pattern: /(?:'unsafe-(?:allow-redirects|dynamic|eval|hash-attributes|hashed-attributes|hashes|inline)'|\*)/i,
          alias: 'function'
        }
      },
      function (e) {
        var t,
        n = /("|')(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/;
        e.languages.css.selector = {
          pattern: e.languages.css.selector.pattern,
          lookbehind: !0,
          inside: t = {
            'pseudo-element': /:(?:after|before|first-letter|first-line|selection)|::[-\w]+/,
            'pseudo-class': /:[-\w]+/,
            class : /\.[-\w]+/,
            id: /#[-\w]+/,
            attribute: {
              pattern: RegExp('\\[(?:[^[\\]"\']|' + n.source + ')*\\]'),
              greedy: !0,
              inside: {
                punctuation: /^\[|\]$/,
                'case-sensitivity': {
                  pattern: /(\s)[si]$/i,
                  lookbehind: !0,
                  alias: 'keyword'
                },
                namespace: {
                  pattern: /^(\s*)(?:(?!\s)[-*\w\xA0-\uFFFF])*\|(?!=)/,
                  lookbehind: !0,
                  inside: {
                    punctuation: /\|$/
                  }
                },
                'attr-name': {
                  pattern: /^(\s*)(?:(?!\s)[-\w\xA0-\uFFFF])+/,
                  lookbehind: !0
                },
                'attr-value': [
                  n,
                  {
                    pattern: /(=\s*)(?:(?!\s)[-\w\xA0-\uFFFF])+(?=\s*$)/,
                    lookbehind: !0
                  }
                ],
                operator: /[|~*^$]?=/
              }
            },
            'n-th': [
              {
                pattern: /(\(\s*)[+-]?\d*[\dn](?:\s*[+-]\s*\d+)?(?=\s*\))/,
                lookbehind: !0,
                inside: {
                  number: /[\dn]+/,
                  operator: /[+-]/
                }
              },
              {
                pattern: /(\(\s*)(?:even|odd)(?=\s*\))/i,
                lookbehind: !0
              }
            ],
            combinator: />|\+|~|\|\|/,
            punctuation: /[(),]/
          }
        },
        e.languages.css.atrule.inside['selector-function-argument'].inside = t,
        e.languages.insertBefore('css', 'property', {
          variable: {
            pattern: /(^|[^-\w\xA0-\uFFFF])--(?!\s)[-_a-z\xA0-\uFFFF](?:(?!\s)[-\w\xA0-\uFFFF])*/i,
            lookbehind: !0
          }
        });
        var a = {
          pattern: /(\b\d+)(?:%|[a-z]+(?![\w-]))/,
          lookbehind: !0
        },
        r = {
          pattern: /(^|[^\w.-])-?(?:\d+(?:\.\d+)?|\.\d+)/,
          lookbehind: !0
        };
        e.languages.insertBefore('css', 'function', {
          operator: {
            pattern: /(\s)[+\-*\/](?=\s)/,
            lookbehind: !0
          },
          hexcode: {
            pattern: /\B#[\da-f]{3,8}\b/i,
            alias: 'color'
          },
          color: [
            {
              pattern: /(^|[^\w-])(?:AliceBlue|AntiqueWhite|Aqua|Aquamarine|Azure|Beige|Bisque|Black|BlanchedAlmond|Blue|BlueViolet|Brown|BurlyWood|CadetBlue|Chartreuse|Chocolate|Coral|CornflowerBlue|Cornsilk|Crimson|Cyan|DarkBlue|DarkCyan|DarkGoldenRod|DarkGr[ae]y|DarkGreen|DarkKhaki|DarkMagenta|DarkOliveGreen|DarkOrange|DarkOrchid|DarkRed|DarkSalmon|DarkSeaGreen|DarkSlateBlue|DarkSlateGr[ae]y|DarkTurquoise|DarkViolet|DeepPink|DeepSkyBlue|DimGr[ae]y|DodgerBlue|FireBrick|FloralWhite|ForestGreen|Fuchsia|Gainsboro|GhostWhite|Gold|GoldenRod|Gr[ae]y|Green|GreenYellow|HoneyDew|HotPink|IndianRed|Indigo|Ivory|Khaki|Lavender|LavenderBlush|LawnGreen|LemonChiffon|LightBlue|LightCoral|LightCyan|LightGoldenRodYellow|LightGr[ae]y|LightGreen|LightPink|LightSalmon|LightSeaGreen|LightSkyBlue|LightSlateGr[ae]y|LightSteelBlue|LightYellow|Lime|LimeGreen|Linen|Magenta|Maroon|MediumAquaMarine|MediumBlue|MediumOrchid|MediumPurple|MediumSeaGreen|MediumSlateBlue|MediumSpringGreen|MediumTurquoise|MediumVioletRed|MidnightBlue|MintCream|MistyRose|Moccasin|NavajoWhite|Navy|OldLace|Olive|OliveDrab|Orange|OrangeRed|Orchid|PaleGoldenRod|PaleGreen|PaleTurquoise|PaleVioletRed|PapayaWhip|PeachPuff|Peru|Pink|Plum|PowderBlue|Purple|Red|RosyBrown|RoyalBlue|SaddleBrown|Salmon|SandyBrown|SeaGreen|SeaShell|Sienna|Silver|SkyBlue|SlateBlue|SlateGr[ae]y|Snow|SpringGreen|SteelBlue|Tan|Teal|Thistle|Tomato|Transparent|Turquoise|Violet|Wheat|White|WhiteSmoke|Yellow|YellowGreen)(?![\w-])/i,
              lookbehind: !0
            },
            {
              pattern: /\b(?:rgb|hsl)\(\s*\d{1,3}\s*,\s*\d{1,3}%?\s*,\s*\d{1,3}%?\s*\)\B|\b(?:rgb|hsl)a\(\s*\d{1,3}\s*,\s*\d{1,3}%?\s*,\s*\d{1,3}%?\s*,\s*(?:0|0?\.\d+|1)\s*\)\B/i,
              inside: {
                unit: a,
                number: r,
                function : /[\w-]+(?=\()/,
                punctuation: /[(),]/
              }
            }
          ],
          entity: /\\[\da-f]{1,8}/i,
          unit: a,
          number: r
        })
      }(d),
      function (e) {
        e.languages.diff = {
          coord: [
            /^(?:\*{3}|-{3}|\+{3}).*$/m,
            /^@@.*@@$/m,
            /^\d.*$/m
          ]
        };
        var t = {
          'deleted-sign': '-',
          'deleted-arrow': '<',
          'inserted-sign': '+',
          'inserted-arrow': '>',
          unchanged: ' ',
          diff: '!'
        };
        Object.keys(t).forEach((function (n) {
          var a = t[n],
          r = [
          ];
          /^\w+$/.test(n) || r.push(/\w+/.exec(n) [0]),
          'diff' === n && r.push('bold'),
          e.languages.diff[n] = {
            pattern: RegExp('^(?:[' + a + '].*(?:\r\n?|\n|(?![\\s\\S])))+', 'm'),
            alias: r,
            inside: {
              line: {
                pattern: /(.)(?=[\s\S]).*(?:\r\n?|\n)?/,
                lookbehind: !0
              },
              prefix: {
                pattern: /[\s\S]/,
                alias: /\w+/.exec(n) [0]
              }
            }
          }
        })),
        Object.defineProperty(e.languages.diff, 'PREFIXES', {
          value: t
        })
      }(d),
      function (e) {
        function t(e, t) {
          return '___' + e.toUpperCase() + t + '___'
        }
        Object.defineProperties(e.languages['markup-templating'] = {
        }, {
          buildPlaceholders: {
            value: function (n, a, r, i) {
              if (n.language === a) {
                var o = n.tokenStack = [
                ];
                n.code = n.code.replace(r, (function (e) {
                  if ('function' == typeof i && !i(e)) return e;
                  for (var r, s = o.length; - 1 !== n.code.indexOf(r = t(a, s)); ) ++s;
                  return o[s] = e,
                  r
                })),
                n.grammar = e.languages.markup
              }
            }
          },
          tokenizePlaceholders: {
            value: function (n, a) {
              if (n.language === a && n.tokenStack) {
                n.grammar = e.languages[a];
                var r = 0,
                i = Object.keys(n.tokenStack);
                !function o(s) {
                  for (var l = 0; l < s.length && !(r >= i.length); l++) {
                    var d = s[l];
                    if ('string' == typeof d || d.content && 'string' == typeof d.content) {
                      var u = i[r],
                      c = n.tokenStack[u],
                      p = 'string' == typeof d ? d : d.content,
                      g = t(a, u),
                      b = p.indexOf(g);
                      if ( - 1 < b) {
                        ++r;
                        var m = p.substring(0, b),
                        f = new e.Token(a, e.tokenize(c, n.grammar), 'language-' + a, c),
                        h = p.substring(b + g.length),
                        E = [
                        ];
                        m && E.push.apply(E, o([m])),
                        E.push(f),
                        h && E.push.apply(E, o([h])),
                        'string' == typeof d ? s.splice.apply(s, [
                          l,
                          1
                        ].concat(E)) : d.content = E
                      }
                    } else d.content && o(d.content)
                  }
                  return s
                }(n.tokens)
              }
            }
          }
        })
      }(d),
      function (e) {
        e.languages.django = {
          comment: /^\{#[\s\S]*?#\}$/,
          tag: {
            pattern: /(^\{%[+-]?\s*)\w+/,
            lookbehind: !0,
            alias: 'keyword'
          },
          delimiter: {
            pattern: /^\{[{%][+-]?|[+-]?[}%]\}$/,
            alias: 'punctuation'
          },
          string: {
            pattern: /("|')(?:\\.|(?!\1)[^\\\r\n])*\1/,
            greedy: !0
          },
          filter: {
            pattern: /(\|)\w+/,
            lookbehind: !0,
            alias: 'function'
          },
          test: {
            pattern: /(\bis\s+(?:not\s+)?)(?!not\b)\w+/,
            lookbehind: !0,
            alias: 'function'
          },
          function : /\b[a-z_]\w+(?=\s*\()/i,
          keyword: /\b(?:and|as|by|else|for|if|import|in|is|loop|not|or|recursive|with|without)\b/,
          operator: /[-+%=]=?|!=|\*\*?=?|\/\/?=?|<[<=>]?|>[=>]?|[&|^~]/,
          number: /\b\d+(?:\.\d+)?\b/,
          boolean: /[Tt]rue|[Ff]alse|[Nn]one/,
          variable: /\b\w+?\b/,
          punctuation: /[{}[\](),.:;]/
        };
        var t = /\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}|\{#[\s\S]*?#\}/g,
        n = e.languages['markup-templating'];
        e.hooks.add('before-tokenize', (function (e) {
          n.buildPlaceholders(e, 'django', t)
        })),
        e.hooks.add('after-tokenize', (function (e) {
          n.tokenizePlaceholders(e, 'django')
        })),
        e.languages.jinja2 = e.languages.django,
        e.hooks.add('before-tokenize', (function (e) {
          n.buildPlaceholders(e, 'jinja2', t)
        })),
        e.hooks.add('after-tokenize', (function (e) {
          n.tokenizePlaceholders(e, 'jinja2')
        }))
      }(d),
      function (e) {
        var t = '(?:[ \t]+(?![ \t])(?:<SP_BS>)?|<SP_BS>)'.replace(/<SP_BS>/g, (function () {
          return '\\\\[\r\n](?:\\s|\\\\[\r\n]|#.*(?!.))*(?![\\s#]|\\\\[\r\n])'
        })),
        n = '"(?:[^"\\\\\r\n]|\\\\(?:\r\n|[^]))*"|\'(?:[^\'\\\\\r\n]|\\\\(?:\r\n|[^]))*\'',
        a = '--[\\w-]+=(?:<STR>|(?!["\'])(?:[^\\s\\\\]|\\\\.)+)'.replace(/<STR>/g, (function () {
          return n
        })),
        r = {
          pattern: RegExp(n),
          greedy: !0
        },
        i = {
          pattern: /(^[ \t]*)#.*/m,
          lookbehind: !0,
          greedy: !0
        };
        function o(e, n) {
          return e = e.replace(/<OPT>/g, (function () {
            return a
          })).replace(/<SP>/g, (function () {
            return t
          })),
          RegExp(e, n)
        }
        e.languages.docker = {
          instruction: {
            pattern: /(^[ \t]*)(?:ADD|ARG|CMD|COPY|ENTRYPOINT|ENV|EXPOSE|FROM|HEALTHCHECK|LABEL|MAINTAINER|ONBUILD|RUN|SHELL|STOPSIGNAL|USER|VOLUME|WORKDIR)(?=\s)(?:\\.|[^\r\n\\])*(?:\\$(?:\s|#.*$)*(?![\s#])(?:\\.|[^\r\n\\])*)*/im,
            lookbehind: !0,
            greedy: !0,
            inside: {
              options: {
                pattern: o('(^(?:ONBUILD<SP>)?\\w+<SP>)<OPT>(?:<SP><OPT>)*', 'i'),
                lookbehind: !0,
                greedy: !0,
                inside: {
                  property: {
                    pattern: /(^|\s)--[\w-]+/,
                    lookbehind: !0
                  },
                  string: [
                    r,
                    {
                      pattern: /(=)(?!["'])(?:[^\s\\]|\\.)+/,
                      lookbehind: !0
                    }
                  ],
                  operator: /\\$/m,
                  punctuation: /=/
                }
              },
              keyword: [
                {
                  pattern: o('(^(?:ONBUILD<SP>)?HEALTHCHECK<SP>(?:<OPT><SP>)*)(?:CMD|NONE)\\b', 'i'),
                  lookbehind: !0,
                  greedy: !0
                },
                {
                  pattern: o('(^(?:ONBUILD<SP>)?FROM<SP>(?:<OPT><SP>)*(?!--)[^ \t\\\\]+<SP>)AS', 'i'),
                  lookbehind: !0,
                  greedy: !0
                },
                {
                  pattern: o('(^ONBUILD<SP>)\\w+', 'i'),
                  lookbehind: !0,
                  greedy: !0
                },
                {
                  pattern: /^\w+/,
                  greedy: !0
                }
              ],
              comment: i,
              string: r,
              variable: /\$(?:\w+|\{[^{}"'\\]*\})/,
              operator: /\\$/m
            }
          },
          comment: i
        },
        e.languages.dockerfile = e.languages.docker
      }(d),
      d.languages.elixir = {
        doc: {
          pattern: /@(?:doc|moduledoc)\s+(?:("""|''')[\s\S]*?\1|("|')(?:\\(?:\r\n|[\s\S])|(?!\2)[^\\\r\n])*\2)/,
          inside: {
            attribute: /^@\w+/,
            string: /['"][\s\S]+/
          }
        },
        comment: {
          pattern: /#.*/m,
          greedy: !0
        },
        regex: {
          pattern: /~[rR](?:("""|''')(?:\\[\s\S]|(?!\1)[^\\])+\1|([\/|"'])(?:\\.|(?!\2)[^\\\r\n])+\2|\((?:\\.|[^\\)\r\n])+\)|\[(?:\\.|[^\\\]\r\n])+\]|\{(?:\\.|[^\\}\r\n])+\}|<(?:\\.|[^\\>\r\n])+>)[uismxfr]*/,
          greedy: !0
        },
        string: [
          {
            pattern: /~[cCsSwW](?:("""|''')(?:\\[\s\S]|(?!\1)[^\\])+\1|([\/|"'])(?:\\.|(?!\2)[^\\\r\n])+\2|\((?:\\.|[^\\)\r\n])+\)|\[(?:\\.|[^\\\]\r\n])+\]|\{(?:\\.|#\{[^}]+\}|#(?!\{)|[^#\\}\r\n])+\}|<(?:\\.|[^\\>\r\n])+>)[csa]?/,
            greedy: !0,
            inside: {
            }
          },
          {
            pattern: /("""|''')[\s\S]*?\1/,
            greedy: !0,
            inside: {
            }
          },
          {
            pattern: /("|')(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/,
            greedy: !0,
            inside: {
            }
          }
        ],
        atom: {
          pattern: /(^|[^:]):\w+/,
          lookbehind: !0,
          alias: 'symbol'
        },
        module: {
          pattern: /\b[A-Z]\w*\b/,
          alias: 'class-name'
        },
        'attr-name': /\b\w+\??:(?!:)/,
        argument: {
          pattern: /(^|[^&])&\d+/,
          lookbehind: !0,
          alias: 'variable'
        },
        attribute: {
          pattern: /@\w+/,
          alias: 'variable'
        },
        function : /\b[_a-zA-Z]\w*[?!]?(?:(?=\s*(?:\.\s*)?\()|(?=\/\d))/,
        number: /\b(?:0[box][a-f\d_]+|\d[\d_]*)(?:\.[\d_]+)?(?:e[+-]?[\d_]+)?\b/i,
        keyword: /\b(?:after|alias|and|case|catch|cond|def(?:callback|delegate|exception|impl|macro|module|n|np|p|protocol|struct)?|do|else|end|fn|for|if|import|not|or|quote|raise|require|rescue|try|unless|unquote|use|when)\b/,
        boolean: /\b(?:true|false|nil)\b/,
        operator: [
          /\bin\b|&&?|\|[|>]?|\\\\|::|\.\.\.?|\+\+?|-[->]?|<[-=>]|>=|!==?|\B!|=(?:==?|[>~])?|[*\/^]/,
          {
            pattern: /([^<])<(?!<)/,
            lookbehind: !0
          },
          {
            pattern: /([^>])>(?!>)/,
            lookbehind: !0
          }
        ],
        punctuation: /<<|>>|[.,%\[\]{}()]/
      },
      d.languages.elixir.string.forEach((function (e) {
        e.inside = {
          interpolation: {
            pattern: /#\{[^}]+\}/,
            inside: {
              delimiter: {
                pattern: /^#\{|\}$/,
                alias: 'punctuation'
              },
              rest: d.languages.elixir
            }
          }
        }
      })),
      d.languages.elm = {
        comment: /--.*|\{-[\s\S]*?-\}/,
        char: {
          pattern: /'(?:[^\\'\r\n]|\\(?:[abfnrtv\\']|\d+|x[0-9a-fA-F]+))'/,
          greedy: !0
        },
        string: [
          {
            pattern: /"""[\s\S]*?"""/,
            greedy: !0
          },
          {
            pattern: /"(?:[^\\"\r\n]|\\.)*"/,
            greedy: !0
          }
        ],
        'import-statement': {
          pattern: /(^[\t ]*)import\s+[A-Z]\w*(?:\.[A-Z]\w*)*(?:\s+as\s+(?:[A-Z]\w*)(?:\.[A-Z]\w*)*)?(?:\s+exposing\s+)?/m,
          lookbehind: !0,
          inside: {
            keyword: /\b(?:import|as|exposing)\b/
          }
        },
        keyword: /\b(?:alias|as|case|else|exposing|if|in|infixl|infixr|let|module|of|then|type)\b/,
        builtin: /\b(?:abs|acos|always|asin|atan|atan2|ceiling|clamp|compare|cos|curry|degrees|e|flip|floor|fromPolar|identity|isInfinite|isNaN|logBase|max|min|negate|never|not|pi|radians|rem|round|sin|sqrt|tan|toFloat|toPolar|toString|truncate|turns|uncurry|xor)\b/,
        number: /\b(?:\d+(?:\.\d+)?(?:e[+-]?\d+)?|0x[0-9a-f]+)\b/i,
        operator: /\s\.\s|[+\-/*=.$<>:&|^?%#@~!]{2,}|[+\-/*=$<>:&|^?%#@~!]/,
        hvariable: /\b(?:[A-Z]\w*\.)*[a-z]\w*\b/,
        constant: /\b(?:[A-Z]\w*\.)*[A-Z]\w*\b/,
        punctuation: /[{}[\]|(),.:]/
      },
      d.languages.erlang = {
        comment: /%.+/,
        string: {
          pattern: /"(?:\\.|[^\\"\r\n])*"/,
          greedy: !0
        },
        'quoted-function': {
          pattern: /'(?:\\.|[^\\'\r\n])+'(?=\()/,
          alias: 'function'
        },
        'quoted-atom': {
          pattern: /'(?:\\.|[^\\'\r\n])+'/,
          alias: 'atom'
        },
        boolean: /\b(?:true|false)\b/,
        keyword: /\b(?:fun|when|case|of|end|if|receive|after|try|catch)\b/,
        number: [
          /\$\\?./,
          /\b\d+#[a-z0-9]+/i,
          /(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[+-]?\d+)?/i
        ],
        function : /\b[a-z][\w@]*(?=\()/,
        variable: {
          pattern: /(^|[^@])(?:\b|\?)[A-Z_][\w@]*/,
          lookbehind: !0
        },
        operator: [
          /[=\/<>:]=|=[:\/]=|\+\+?|--?|[=*\/!]|\b(?:bnot|div|rem|band|bor|bxor|bsl|bsr|not|and|or|xor|orelse|andalso)\b/,
          {
            pattern: /(^|[^<])<(?!<)/,
            lookbehind: !0
          },
          {
            pattern: /(^|[^>])>(?!>)/,
            lookbehind: !0
          }
        ],
        atom: /\b[a-z][\w@]*/,
        punctuation: /[()[\]{}:;,.#|]|<<|>>/
      },
      d.languages.fsharp = d.languages.extend('clike', {
        comment: [
          {
            pattern: /(^|[^\\])\(\*(?!\))[\s\S]*?\*\)/,
            lookbehind: !0
          },
          {
            pattern: /(^|[^\\:])\/\/.*/,
            lookbehind: !0
          }
        ],
        string: {
          pattern: /(?:"""[\s\S]*?"""|@"(?:""|[^"])*"|"(?:\\[\s\S]|[^\\"])*")B?|'(?:[^\\']|\\(?:.|\d{3}|x[a-fA-F\d]{2}|u[a-fA-F\d]{4}|U[a-fA-F\d]{8}))'B?/,
          greedy: !0
        },
        'class-name': {
          pattern: /(\b(?:exception|inherit|interface|new|of|type)\s+|\w\s*:\s*|\s:\??>\s*)[.\w]+\b(?:\s*(?:->|\*)\s*[.\w]+\b)*(?!\s*[:.])/,
          lookbehind: !0,
          inside: {
            operator: /->|\*/,
            punctuation: /\./
          }
        },
        keyword: /\b(?:let|return|use|yield)(?:!\B|\b)|\b(?:abstract|and|as|assert|base|begin|class|default|delegate|do|done|downcast|downto|elif|else|end|exception|extern|false|finally|for|fun|function|global|if|in|inherit|inline|interface|internal|lazy|match|member|module|mutable|namespace|new|not|null|of|open|or|override|private|public|rec|select|static|struct|then|to|true|try|type|upcast|val|void|when|while|with|asr|land|lor|lsl|lsr|lxor|mod|sig|atomic|break|checked|component|const|constraint|constructor|continue|eager|event|external|fixed|functor|include|method|mixin|object|parallel|process|protected|pure|sealed|tailcall|trait|virtual|volatile)\b/,
        number: [
          /\b0x[\da-fA-F]+(?:un|lf|LF)?\b/,
          /\b0b[01]+(?:y|uy)?\b/,
          /(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:[fm]|e[+-]?\d+)?\b/i,
          /\b\d+(?:[IlLsy]|u[lsy]?|UL)?\b/
        ],
        operator: /([<>~&^])\1\1|([*.:<>&])\2|<-|->|[!=:]=|<?\|{1,3}>?|\??(?:<=|>=|<>|[-+*/%=<>])\??|[!?^&]|~[+~-]|:>|:\?>?/
      }),
      d.languages.insertBefore('fsharp', 'keyword', {
        preprocessor: {
          pattern: /(^[\t ]*)#.*/m,
          lookbehind: !0,
          alias: 'property',
          inside: {
            directive: {
              pattern: /(^#)\b(?:else|endif|if|light|line|nowarn)\b/,
              lookbehind: !0,
              alias: 'keyword'
            }
          }
        }
      }),
      d.languages.insertBefore('fsharp', 'punctuation', {
        'computation-expression': {
          pattern: /\b[_a-z]\w*(?=\s*\{)/i,
          alias: 'keyword'
        }
      }),
      d.languages.insertBefore('fsharp', 'string', {
        annotation: {
          pattern: /\[<.+?>\]/,
          inside: {
            punctuation: /^\[<|>\]$/,
            'class-name': {
              pattern: /^\w+$|(^|;\s*)[A-Z]\w*(?=\()/,
              lookbehind: !0
            },
            'annotation-content': {
              pattern: /[\s\S]+/,
              inside: d.languages.fsharp
            }
          }
        }
      }),
      (o = d).languages.flow = o.languages.extend('javascript', {
      }),
      o.languages.insertBefore('flow', 'keyword', {
        type: [
          {
            pattern: /\b(?:[Nn]umber|[Ss]tring|[Bb]oolean|Function|any|mixed|null|void)\b/,
            alias: 'tag'
          }
        ]
      }),
      o.languages.flow['function-variable'].pattern = /(?!\s)[_$a-z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*=\s*(?:function\b|(?:\([^()]*\)(?:\s*:\s*\w+)?|(?!\s)[_$a-z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*)\s*=>))/i,
      delete o.languages.flow.parameter,
      o.languages.insertBefore('flow', 'operator', {
        'flow-punctuation': {
          pattern: /\{\||\|\}/,
          alias: 'punctuation'
        }
      }),
      Array.isArray(o.languages.flow.keyword) || (o.languages.flow.keyword = [
        o.languages.flow.keyword
      ]),
      o.languages.flow.keyword.unshift({
        pattern: /(^|[^$]\b)(?:type|opaque|declare|Class)\b(?!\$)/,
        lookbehind: !0
      }, {
        pattern: /(^|[^$]\B)\$(?:await|Diff|Exact|Keys|ObjMap|PropertyType|Shape|Record|Supertype|Subtype|Enum)\b(?!\$)/,
        lookbehind: !0
      }),
      d.languages.git = {
        comment: /^#.*/m,
        deleted: /^[-–].*/m,
        inserted: /^\+.*/m,
        string: /("|')(?:\\.|(?!\1)[^\\\r\n])*\1/m,
        command: {
          pattern: /^.*\$ git .*$/m,
          inside: {
            parameter: /\s--?\w+/m
          }
        },
        coord: /^@@.*@@$/m,
        'commit-sha1': /^commit \w{40}$/m
      },
      d.languages.go = d.languages.extend('clike', {
        string: {
          pattern: /(["'`])(?:\\[\s\S]|(?!\1)[^\\])*\1/,
          greedy: !0
        },
        keyword: /\b(?:break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go(?:to)?|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b/,
        boolean: /\b(?:_|iota|nil|true|false)\b/,
        number: /(?:\b0x[a-f\d]+|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[-+]?\d+)?)i?/i,
        operator: /[*\/%^!=]=?|\+[=+]?|-[=-]?|\|[=|]?|&(?:=|&|\^=?)?|>(?:>=?|=)?|<(?:<=?|=|-)?|:=|\.\.\./,
        builtin: /\b(?:bool|byte|complex(?:64|128)|error|float(?:32|64)|rune|string|u?int(?:8|16|32|64)?|uintptr|append|cap|close|complex|copy|delete|imag|len|make|new|panic|print(?:ln)?|real|recover)\b/
      }),
      delete d.languages.go['class-name'],
      d.languages.graphql = {
        comment: /#.*/,
        description: {
          pattern: /(?:"""(?:[^"]|(?!""")")*"""|"(?:\\.|[^\\"\r\n])*")(?=\s*[a-z_])/i,
          greedy: !0,
          alias: 'string',
          inside: {
            'language-markdown': {
              pattern: /(^"(?:"")?)(?!\1)[\s\S]+(?=\1$)/,
              lookbehind: !0,
              inside: d.languages.markdown
            }
          }
        },
        string: {
          pattern: /"""(?:[^"]|(?!""")")*"""|"(?:\\.|[^\\"\r\n])*"/,
          greedy: !0
        },
        number: /(?:\B-|\b)\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/i,
        boolean: /\b(?:true|false)\b/,
        variable: /\$[a-z_]\w*/i,
        directive: {
          pattern: /@[a-z_]\w*/i,
          alias: 'function'
        },
        'attr-name': {
          pattern: /[a-z_]\w*(?=\s*(?:\((?:[^()"]|"(?:\\.|[^\\"\r\n])*")*\))?:)/i,
          greedy: !0
        },
        'atom-input': {
          pattern: /[A-Z]\w*Input(?=!?.*$)/m,
          alias: 'class-name'
        },
        scalar: /\b(?:Boolean|Float|ID|Int|String)\b/,
        constant: /\b[A-Z][A-Z_\d]*\b/,
        'class-name': {
          pattern: /(\b(?:enum|implements|interface|on|scalar|type|union)\s+|&\s*|:\s*|\[)[A-Z_]\w*/,
          lookbehind: !0
        },
        fragment: {
          pattern: /(\bfragment\s+|\.{3}\s*(?!on\b))[a-zA-Z_]\w*/,
          lookbehind: !0,
          alias: 'function'
        },
        'definition-mutation': {
          pattern: /(\bmutation\s+)[a-zA-Z_]\w*/,
          lookbehind: !0,
          alias: 'function'
        },
        'definition-query': {
          pattern: /(\bquery\s+)[a-zA-Z_]\w*/,
          lookbehind: !0,
          alias: 'function'
        },
        keyword: /\b(?:directive|enum|extend|fragment|implements|input|interface|mutation|on|query|repeatable|scalar|schema|subscription|type|union)\b/,
        operator: /[!=|&]|\.{3}/,
        'property-query': /\w+(?=\s*\()/,
        object: /\w+(?=\s*\{)/,
        punctuation: /[!(){}\[\]:=,]/,
        property: /\w+/
      },
      d.hooks.add('after-tokenize', (function (e) {
        if ('graphql' === e.language) for (var t = e.tokens.filter((function (e) {
          return 'string' != typeof e && 'comment' !== e.type && 'scalar' !== e.type
        })), n = 0; n < t.length; ) {
          var a = t[n++];
          if ('keyword' === a.type && 'mutation' === a.content) {
            var r = [
            ];
            if (c(['definition-mutation',
            'punctuation']) && '(' === u(1).content) {
              n += 2;
              var i = p(/^\($/, /^\)$/);
              if ( - 1 === i) continue;
              for (; n < i; n++) {
                var o = u(0);
                'variable' === o.type && (g(o, 'variable-input'), r.push(o.content))
              }
              n = i + 1
            }
            if (c(['punctuation',
            'property-query']) && '{' === u(0).content && (n++, g(u(0), 'property-mutation'), 0 < r.length)) {
              var s = p(/^\{$/, /^\}$/);
              if ( - 1 === s) continue;
              for (var l = n; l < s; l++) {
                var d = t[l];
                'variable' === d.type && 0 <= r.indexOf(d.content) && g(d, 'variable-input')
              }
            }
          }
        }
        function u(e) {
          return t[n + e]
        }
        function c(e, t) {
          t = t || 0;
          for (var n = 0; n < e.length; n++) {
            var a = u(n + t);
            if (!a || a.type !== e[n]) return !1
          }
          return !0
        }
        function p(e, a) {
          for (var r = 1, i = n; i < t.length; i++) {
            var o = t[i],
            s = o.content;
            if ('punctuation' === o.type && 'string' == typeof s) if (e.test(s)) r++;
             else if (a.test(s) && 0 == --r) return i
          }
          return - 1
        }
        function g(e, t) {
          var n = e.alias;
          n ? Array.isArray(n) || (e.alias = n = [
            n
          ]) : e.alias = n = [
          ],
          n.push(t)
        }
      })),
      function (e) {
        e.languages.ruby = e.languages.extend('clike', {
          comment: [
            /#.*/,
            {
              pattern: /^=begin\s[\s\S]*?^=end/m,
              greedy: !0
            }
          ],
          'class-name': {
            pattern: /(\b(?:class)\s+|\bcatch\s+\()[\w.\\]+/i,
            lookbehind: !0,
            inside: {
              punctuation: /[.\\]/
            }
          },
          keyword: /\b(?:alias|and|BEGIN|begin|break|case|class|def|define_method|defined|do|each|else|elsif|END|end|ensure|extend|for|if|in|include|module|new|next|nil|not|or|prepend|protected|private|public|raise|redo|require|rescue|retry|return|self|super|then|throw|undef|unless|until|when|while|yield)\b/
        });
        var t = {
          pattern: /#\{[^}]+\}/,
          inside: {
            delimiter: {
              pattern: /^#\{|\}$/,
              alias: 'tag'
            },
            rest: e.languages.ruby
          }
        };
        delete e.languages.ruby.function,
        e.languages.insertBefore('ruby', 'keyword', {
          regex: [
            {
              pattern: RegExp('%r(?:' + ['([^a-zA-Z0-9\\s{(\\[<])(?:(?!\\1)[^\\\\]|\\\\[^])*\\1',
              '\\((?:[^()\\\\]|\\\\[^])*\\)',
              '\\{(?:[^#{}\\\\]|#(?:\\{[^}]+\\})?|\\\\[^])*\\}',
              '\\[(?:[^\\[\\]\\\\]|\\\\[^])*\\]',
              '<(?:[^<>\\\\]|\\\\[^])*>'].join('|') + ')[egimnosux]{0,6}'),
              greedy: !0,
              inside: {
                interpolation: t
              }
            },
            {
              pattern: /(^|[^/])\/(?!\/)(?:\[[^\r\n\]]+\]|\\.|[^[/\\\r\n])+\/[egimnosux]{0,6}(?=\s*(?:$|[\r\n,.;})#]))/,
              lookbehind: !0,
              greedy: !0,
              inside: {
                interpolation: t
              }
            }
          ],
          variable: /[@$]+[a-zA-Z_]\w*(?:[?!]|\b)/,
          symbol: {
            pattern: /(^|[^:]):[a-zA-Z_]\w*(?:[?!]|\b)/,
            lookbehind: !0
          },
          'method-definition': {
            pattern: /(\bdef\s+)[\w.]+/,
            lookbehind: !0,
            inside: {
              function : /\w+$/,
              rest: e.languages.ruby
            }
          }
        }),
        e.languages.insertBefore('ruby', 'number', {
          builtin: /\b(?:Array|Bignum|Binding|Class|Continuation|Dir|Exception|FalseClass|File|Stat|Fixnum|Float|Hash|Integer|IO|MatchData|Method|Module|NilClass|Numeric|Object|Proc|Range|Regexp|String|Struct|TMS|Symbol|ThreadGroup|Thread|Time|TrueClass)\b/,
          constant: /\b[A-Z]\w*(?:[?!]|\b)/
        }),
        e.languages.ruby.string = [
          {
            pattern: RegExp('%[qQiIwWxs]?(?:' + ['([^a-zA-Z0-9\\s{(\\[<])(?:(?!\\1)[^\\\\]|\\\\[^])*\\1',
            '\\((?:[^()\\\\]|\\\\[^])*\\)',
            '\\{(?:[^#{}\\\\]|#(?:\\{[^}]+\\})?|\\\\[^])*\\}',
            '\\[(?:[^\\[\\]\\\\]|\\\\[^])*\\]',
            '<(?:[^<>\\\\]|\\\\[^])*>'].join('|') + ')'),
            greedy: !0,
            inside: {
              interpolation: t
            }
          },
          {
            pattern: /("|')(?:#\{[^}]+\}|#(?!\{)|\\(?:\r\n|[\s\S])|(?!\1)[^\\#\r\n])*\1/,
            greedy: !0,
            inside: {
              interpolation: t
            }
          },
          {
            pattern: /<<[-~]?([a-z_]\w*)[\r\n](?:.*[\r\n])*?[\t ]*\1/i,
            alias: 'heredoc-string',
            greedy: !0,
            inside: {
              delimiter: {
                pattern: /^<<[-~]?[a-z_]\w*|[a-z_]\w*$/i,
                alias: 'symbol',
                inside: {
                  punctuation: /^<<[-~]?/
                }
              },
              interpolation: t
            }
          },
          {
            pattern: /<<[-~]?'([a-z_]\w*)'[\r\n](?:.*[\r\n])*?[\t ]*\1/i,
            alias: 'heredoc-string',
            greedy: !0,
            inside: {
              delimiter: {
                pattern: /^<<[-~]?'[a-z_]\w*'|[a-z_]\w*$/i,
                alias: 'symbol',
                inside: {
                  punctuation: /^<<[-~]?'|'$/
                }
              }
            }
          }
        ],
        e.languages.rb = e.languages.ruby
      }(d),
      function (e) {
        e.languages.haml = {
          'multiline-comment': {
            pattern: /((?:^|\r?\n|\r)([\t ]*))(?:\/|-#).*(?:(?:\r?\n|\r)\2[\t ].+)*/,
            lookbehind: !0,
            alias: 'comment'
          },
          'multiline-code': [
            {
              pattern: /((?:^|\r?\n|\r)([\t ]*)(?:[~-]|[&!]?=)).*,[\t ]*(?:(?:\r?\n|\r)\2[\t ].*,[\t ]*)*(?:(?:\r?\n|\r)\2[\t ].+)/,
              lookbehind: !0,
              inside: e.languages.ruby
            },
            {
              pattern: /((?:^|\r?\n|\r)([\t ]*)(?:[~-]|[&!]?=)).*\|[\t ]*(?:(?:\r?\n|\r)\2[\t ].*\|[\t ]*)*/,
              lookbehind: !0,
              inside: e.languages.ruby
            }
          ],
          filter: {
            pattern: /((?:^|\r?\n|\r)([\t ]*)):[\w-]+(?:(?:\r?\n|\r)(?:\2[\t ].+|\s*?(?=\r?\n|\r)))+/,
            lookbehind: !0,
            inside: {
              'filter-name': {
                pattern: /^:[\w-]+/,
                alias: 'variable'
              }
            }
          },
          markup: {
            pattern: /((?:^|\r?\n|\r)[\t ]*)<.+/,
            lookbehind: !0,
            inside: e.languages.markup
          },
          doctype: {
            pattern: /((?:^|\r?\n|\r)[\t ]*)!!!(?: .+)?/,
            lookbehind: !0
          },
          tag: {
            pattern: /((?:^|\r?\n|\r)[\t ]*)[%.#][\w\-#.]*[\w\-](?:\([^)]+\)|\{(?:\{[^}]+\}|[^{}])+\}|\[[^\]]+\])*[\/<>]*/,
            lookbehind: !0,
            inside: {
              attributes: [
                {
                  pattern: /(^|[^#])\{(?:\{[^}]+\}|[^{}])+\}/,
                  lookbehind: !0,
                  inside: e.languages.ruby
                },
                {
                  pattern: /\([^)]+\)/,
                  inside: {
                    'attr-value': {
                      pattern: /(=\s*)(?:"(?:\\.|[^\\"\r\n])*"|[^)\s]+)/,
                      lookbehind: !0
                    },
                    'attr-name': /[\w:-]+(?=\s*!?=|\s*[,)])/,
                    punctuation: /[=(),]/
                  }
                },
                {
                  pattern: /\[[^\]]+\]/,
                  inside: e.languages.ruby
                }
              ],
              punctuation: /[<>]/
            }
          },
          code: {
            pattern: /((?:^|\r?\n|\r)[\t ]*(?:[~-]|[&!]?=)).+/,
            lookbehind: !0,
            inside: e.languages.ruby
          },
          interpolation: {
            pattern: /#\{[^}]+\}/,
            inside: {
              delimiter: {
                pattern: /^#\{|\}$/,
                alias: 'punctuation'
              },
              rest: e.languages.ruby
            }
          },
          punctuation: {
            pattern: /((?:^|\r?\n|\r)[\t ]*)[~=\-&!]+/,
            lookbehind: !0
          }
        };
        for (var t = [
          'css',
          {
            filter: 'coffee',
            language: 'coffeescript'
          },
          'erb',
          'javascript',
          'less',
          'markdown',
          'ruby',
          'scss',
          'textile'
        ], n = {
        }, a = 0, r = t.length; a < r; a++) {
          var i = t[a];
          i = 'string' == typeof i ? {
            filter: i,
            language: i
          }
           : i,
          e.languages[i.language] && (n['filter-' + i.filter] = {
            pattern: RegExp('((?:^|\\r?\\n|\\r)([\\t ]*)):{{filter_name}}(?:(?:\\r?\\n|\\r)(?:\\2[\\t ].+|\\s*?(?=\\r?\\n|\\r)))+'.replace('{{filter_name}}', (function () {
              return i.filter
            }))),
            lookbehind: !0,
            inside: {
              'filter-name': {
                pattern: /^:[\w-]+/,
                alias: 'variable'
              },
              rest: e.languages[i.language]
            }
          })
        }
        e.languages.insertBefore('haml', 'filter', n)
      }(d),
      function (e) {
        e.languages.handlebars = {
          comment: /\{\{![\s\S]*?\}\}/,
          delimiter: {
            pattern: /^\{\{\{?|\}\}\}?$/i,
            alias: 'punctuation'
          },
          string: /(["'])(?:\\.|(?!\1)[^\\\r\n])*\1/,
          number: /\b0x[\dA-Fa-f]+\b|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:[Ee][+-]?\d+)?/,
          boolean: /\b(?:true|false)\b/,
          block: {
            pattern: /^(\s*(?:~\s*)?)[#\/]\S+?(?=\s*(?:~\s*)?$|\s)/i,
            lookbehind: !0,
            alias: 'keyword'
          },
          brackets: {
            pattern: /\[[^\]]+\]/,
            inside: {
              punctuation: /\[|\]/,
              variable: /[\s\S]+/
            }
          },
          punctuation: /[!"#%&':()*+,.\/;<=>@\[\\\]^`{|}~]/,
          variable: /[^!"#%&'()*+,\/;<=>@\[\\\]^`{|}~\s]+/
        },
        e.hooks.add('before-tokenize', (function (t) {
          e.languages['markup-templating'].buildPlaceholders(t, 'handlebars', /\{\{\{[\s\S]+?\}\}\}|\{\{[\s\S]+?\}\}/g)
        })),
        e.hooks.add('after-tokenize', (function (t) {
          e.languages['markup-templating'].tokenizePlaceholders(t, 'handlebars')
        })),
        e.languages.hbs = e.languages.handlebars
      }(d),
      d.languages.haskell = {
        comment: {
          pattern: /(^|[^-!#$%*+=?&@|~.:<>^\\\/])(?:--(?:(?=.)[^-!#$%*+=?&@|~.:<>^\\\/].*|$)|\{-[\s\S]*?-\})/m,
          lookbehind: !0
        },
        char: {
          pattern: /'(?:[^\\']|\\(?:[abfnrtv\\"'&]|\^[A-Z@[\]^_]|NUL|SOH|STX|ETX|EOT|ENQ|ACK|BEL|BS|HT|LF|VT|FF|CR|SO|SI|DLE|DC1|DC2|DC3|DC4|NAK|SYN|ETB|CAN|EM|SUB|ESC|FS|GS|RS|US|SP|DEL|\d+|o[0-7]+|x[0-9a-fA-F]+))'/,
          alias: 'string'
        },
        string: {
          pattern: /"(?:[^\\"]|\\(?:\S|\s+\\))*"/,
          greedy: !0
        },
        keyword: /\b(?:case|class|data|deriving|do|else|if|in|infixl|infixr|instance|let|module|newtype|of|primitive|then|type|where)\b/,
        'import-statement': {
          pattern: /(^[\t ]*)import\s+(?:qualified\s+)?(?:[A-Z][\w']*)(?:\.[A-Z][\w']*)*(?:\s+as\s+(?:[A-Z][\w']*)(?:\.[A-Z][\w']*)*)?(?:\s+hiding\b)?/m,
          lookbehind: !0,
          inside: {
            keyword: /\b(?:import|qualified|as|hiding)\b/,
            punctuation: /\./
          }
        },
        builtin: /\b(?:abs|acos|acosh|all|and|any|appendFile|approxRational|asTypeOf|asin|asinh|atan|atan2|atanh|basicIORun|break|catch|ceiling|chr|compare|concat|concatMap|const|cos|cosh|curry|cycle|decodeFloat|denominator|digitToInt|div|divMod|drop|dropWhile|either|elem|encodeFloat|enumFrom|enumFromThen|enumFromThenTo|enumFromTo|error|even|exp|exponent|fail|filter|flip|floatDigits|floatRadix|floatRange|floor|fmap|foldl|foldl1|foldr|foldr1|fromDouble|fromEnum|fromInt|fromInteger|fromIntegral|fromRational|fst|gcd|getChar|getContents|getLine|group|head|id|inRange|index|init|intToDigit|interact|ioError|isAlpha|isAlphaNum|isAscii|isControl|isDenormalized|isDigit|isHexDigit|isIEEE|isInfinite|isLower|isNaN|isNegativeZero|isOctDigit|isPrint|isSpace|isUpper|iterate|last|lcm|length|lex|lexDigits|lexLitChar|lines|log|logBase|lookup|map|mapM|mapM_|max|maxBound|maximum|maybe|min|minBound|minimum|mod|negate|not|notElem|null|numerator|odd|or|ord|otherwise|pack|pi|pred|primExitWith|print|product|properFraction|putChar|putStr|putStrLn|quot|quotRem|range|rangeSize|read|readDec|readFile|readFloat|readHex|readIO|readInt|readList|readLitChar|readLn|readOct|readParen|readSigned|reads|readsPrec|realToFrac|recip|rem|repeat|replicate|return|reverse|round|scaleFloat|scanl|scanl1|scanr|scanr1|seq|sequence|sequence_|show|showChar|showInt|showList|showLitChar|showParen|showSigned|showString|shows|showsPrec|significand|signum|sin|sinh|snd|sort|span|splitAt|sqrt|subtract|succ|sum|tail|take|takeWhile|tan|tanh|threadToIOResult|toEnum|toInt|toInteger|toLower|toRational|toUpper|truncate|uncurry|undefined|unlines|until|unwords|unzip|unzip3|userError|words|writeFile|zip|zip3|zipWith|zipWith3)\b/,
        number: /\b(?:\d+(?:\.\d+)?(?:e[+-]?\d+)?|0o[0-7]+|0x[0-9a-f]+)\b/i,
        operator: [
          {
            pattern: /`(?:[A-Z][\w']*\.)*[_a-z][\w']*`/,
            greedy: !0
          },
          {
            pattern: /(\s)\.(?=\s)/,
            lookbehind: !0
          },
          /[-!#$%*+=?&@|~:<>^\\\/][-!#$%*+=?&@|~.:<>^\\\/]*|\.[-!#$%*+=?&@|~.:<>^\\\/]+/
        ],
        hvariable: {
          pattern: /\b(?:[A-Z][\w']*\.)*[_a-z][\w']*/,
          inside: {
            punctuation: /\./
          }
        },
        constant: {
          pattern: /\b(?:[A-Z][\w']*\.)*[A-Z][\w']*/,
          inside: {
            punctuation: /\./
          }
        },
        punctuation: /[{}[\];(),.:]/
      },
      d.languages.hs = d.languages.haskell,
      function (e) {
        e.languages.http = {
          'request-line': {
            pattern: /^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PRI|SEARCH)\s(?:https?:\/\/|\/)\S*\sHTTP\/[0-9.]+/m,
            inside: {
              method: {
                pattern: /^[A-Z]+\b/,
                alias: 'property'
              },
              'request-target': {
                pattern: /^(\s)(?:https?:\/\/|\/)\S*(?=\s)/,
                lookbehind: !0,
                alias: 'url',
                inside: e.languages.uri
              },
              'http-version': {
                pattern: /^(\s)HTTP\/[0-9.]+/,
                lookbehind: !0,
                alias: 'property'
              }
            }
          },
          'response-status': {
            pattern: /^HTTP\/[0-9.]+ \d+ .+/m,
            inside: {
              'http-version': {
                pattern: /^HTTP\/[0-9.]+/,
                alias: 'property'
              },
              'status-code': {
                pattern: /^(\s)\d+(?=\s)/,
                lookbehind: !0,
                alias: 'number'
              },
              'reason-phrase': {
                pattern: /^(\s).+/,
                lookbehind: !0,
                alias: 'string'
              }
            }
          },
          'header-name': {
            pattern: /^[\w-]+:(?=.)/m,
            alias: 'keyword'
          }
        };
        var t,
        n,
        a,
        r = e.languages,
        i = {
          'application/javascript': r.javascript,
          'application/json': r.json || r.javascript,
          'application/xml': r.xml,
          'text/xml': r.xml,
          'text/html': r.html,
          'text/css': r.css
        },
        o = {
          'application/json': !0,
          'application/xml': !0
        };
        for (var s in i) if (i[s]) {
          t = t || {
          };
          var l = o[s] ? (a = (n = s).replace(/^[a-z]+\//, ''), '(?:' + n + '|\\w+/(?:[\\w.-]+\\+)+' + a + '(?![+\\w.-]))') : s;
          t[s.replace(/\//g, '-')] = {
            pattern: RegExp('(content-type:\\s*' + l + '(?:(?:\\r\\n?|\\n).+)*)(?:\\r?\\n|\\r){2}[\\s\\S]*', 'i'),
            lookbehind: !0,
            inside: i[s]
          }
        }
        t && e.languages.insertBefore('http', 'header-name', t)
      }(d),
      function (e) {
        var t = /\b(?:abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|exports|extends|final|finally|float|for|goto|if|implements|import|instanceof|int|interface|long|module|native|new|non-sealed|null|open|opens|package|permits|private|protected|provides|public|record|requires|return|sealed|short|static|strictfp|super|switch|synchronized|this|throw|throws|to|transient|transitive|try|uses|var|void|volatile|while|with|yield)\b/,
        n = '(^|[^\\w.])(?:[a-z]\\w*\\s*\\.\\s*)*(?:[A-Z]\\w*\\s*\\.\\s*)*',
        a = {
          pattern: RegExp(n + '[A-Z](?:[\\d_A-Z]*[a-z]\\w*)?\\b'),
          lookbehind: !0,
          inside: {
            namespace: {
              pattern: /^[a-z]\w*(?:\s*\.\s*[a-z]\w*)*(?:\s*\.)?/,
              inside: {
                punctuation: /\./
              }
            },
            punctuation: /\./
          }
        };
        e.languages.java = e.languages.extend('clike', {
          'class-name': [
            a,
            {
              pattern: RegExp(n + '[A-Z]\\w*(?=\\s+\\w+\\s*[;,=()])'),
              lookbehind: !0,
              inside: a.inside
            }
          ],
          keyword: t,
          function : [
            e.languages.clike.function,
            {
              pattern: /(::\s*)[a-z_]\w*/,
              lookbehind: !0
            }
          ],
          number: /\b0b[01][01_]*L?\b|\b0x(?:\.[\da-f_p+-]+|[\da-f_]+(?:\.[\da-f_p+-]+)?)\b|(?:\b\d[\d_]*(?:\.[\d_]*)?|\B\.\d[\d_]*)(?:e[+-]?\d[\d_]*)?[dfl]?/i,
          operator: {
            pattern: /(^|[^.])(?:<<=?|>>>?=?|->|--|\+\+|&&|\|\||::|[?:~]|[-+*/%&|^!=<>]=?)/m,
            lookbehind: !0
          }
        }),
        e.languages.insertBefore('java', 'string', {
          'triple-quoted-string': {
            pattern: /"""[ \t]*[\r\n](?:(?:"|"")?(?:\\.|[^"\\]))*"""/,
            greedy: !0,
            alias: 'string'
          }
        }),
        e.languages.insertBefore('java', 'class-name', {
          annotation: {
            pattern: /(^|[^.])@\w+(?:\s*\.\s*\w+)*/,
            lookbehind: !0,
            alias: 'punctuation'
          },
          generics: {
            pattern: /<(?:[\w\s,.?]|&(?!&)|<(?:[\w\s,.?]|&(?!&)|<(?:[\w\s,.?]|&(?!&)|<(?:[\w\s,.?]|&(?!&))*>)*>)*>)*>/,
            inside: {
              'class-name': a,
              keyword: t,
              punctuation: /[<>(),.:]/,
              operator: /[?&|]/
            }
          },
          namespace: {
            pattern: RegExp('(\\b(?:exports|import(?:\\s+static)?|module|open|opens|package|provides|requires|to|transitive|uses|with)\\s+)(?!<keyword>)[a-z]\\w*(?:\\.[a-z]\\w*)*\\.?'.replace(/<keyword>/g, (function () {
              return t.source
            }))),
            lookbehind: !0,
            inside: {
              punctuation: /\./
            }
          }
        })
      }(d),
      d.languages.json = {
        property: {
          pattern: /(^|[^\\])"(?:\\.|[^\\"\r\n])*"(?=\s*:)/,
          lookbehind: !0,
          greedy: !0
        },
        string: {
          pattern: /(^|[^\\])"(?:\\.|[^\\"\r\n])*"(?!\s*:)/,
          lookbehind: !0,
          greedy: !0
        },
        comment: {
          pattern: /\/\/.*|\/\*[\s\S]*?(?:\*\/|$)/,
          greedy: !0
        },
        number: /-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/i,
        punctuation: /[{}[\],]/,
        operator: /:/,
        boolean: /\b(?:true|false)\b/,
        null: {
          pattern: /\bnull\b/,
          alias: 'keyword'
        }
      },
      d.languages.webmanifest = d.languages.json,
      function (e) {
        e.languages.kotlin = e.languages.extend('clike', {
          keyword: {
            pattern: /(^|[^.])\b(?:abstract|actual|annotation|as|break|by|catch|class|companion|const|constructor|continue|crossinline|data|do|dynamic|else|enum|expect|external|final|finally|for|fun|get|if|import|in|infix|init|inline|inner|interface|internal|is|lateinit|noinline|null|object|open|operator|out|override|package|private|protected|public|reified|return|sealed|set|super|suspend|tailrec|this|throw|to|try|typealias|val|var|vararg|when|where|while)\b/,
            lookbehind: !0
          },
          function : [
            {
              pattern: /(?:`[^\r\n`]+`|\b\w+)(?=\s*\()/,
              greedy: !0
            },
            {
              pattern: /(\.)(?:`[^\r\n`]+`|\w+)(?=\s*\{)/,
              lookbehind: !0,
              greedy: !0
            }
          ],
          number: /\b(?:0[xX][\da-fA-F]+(?:_[\da-fA-F]+)*|0[bB][01]+(?:_[01]+)*|\d+(?:_\d+)*(?:\.\d+(?:_\d+)*)?(?:[eE][+-]?\d+(?:_\d+)*)?[fFL]?)\b/,
          operator: /\+[+=]?|-[-=>]?|==?=?|!(?:!|==?)?|[\/*%<>]=?|[?:]:?|\.\.|&&|\|\||\b(?:and|inv|or|shl|shr|ushr|xor)\b/
        }),
        delete e.languages.kotlin['class-name'],
        e.languages.insertBefore('kotlin', 'string', {
          'raw-string': {
            pattern: /("""|''')[\s\S]*?\1/,
            alias: 'string'
          }
        }),
        e.languages.insertBefore('kotlin', 'keyword', {
          annotation: {
            pattern: /\B@(?:\w+:)?(?:[A-Z]\w*|\[[^\]]+\])/,
            alias: 'builtin'
          }
        }),
        e.languages.insertBefore('kotlin', 'function', {
          label: {
            pattern: /\b\w+@|@\w+\b/,
            alias: 'symbol'
          }
        });
        var t = [
          {
            pattern: /\$\{[^}]+\}/,
            inside: {
              delimiter: {
                pattern: /^\$\{|\}$/,
                alias: 'variable'
              },
              rest: e.languages.kotlin
            }
          },
          {
            pattern: /\$\w+/,
            alias: 'variable'
          }
        ];
        e.languages.kotlin.string.inside = e.languages.kotlin['raw-string'].inside = {
          interpolation: t
        },
        e.languages.kt = e.languages.kotlin,
        e.languages.kts = e.languages.kotlin
      }(d),
      function (e) {
        var t = /\\(?:[^a-z()[\]]|[a-z*]+)/i,
        n = {
          'equation-command': {
            pattern: t,
            alias: 'regex'
          }
        };
        e.languages.latex = {
          comment: /%.*/m,
          cdata: {
            pattern: /(\\begin\{((?:verbatim|lstlisting)\*?)\})[\s\S]*?(?=\\end\{\2\})/,
            lookbehind: !0
          },
          equation: [
            {
              pattern: /\$\$(?:\\[\s\S]|[^\\$])+\$\$|\$(?:\\[\s\S]|[^\\$])+\$|\\\([\s\S]*?\\\)|\\\[[\s\S]*?\\\]/,
              inside: n,
              alias: 'string'
            },
            {
              pattern: /(\\begin\{((?:equation|math|eqnarray|align|multline|gather)\*?)\})[\s\S]*?(?=\\end\{\2\})/,
              lookbehind: !0,
              inside: n,
              alias: 'string'
            }
          ],
          keyword: {
            pattern: /(\\(?:begin|end|ref|cite|label|usepackage|documentclass)(?:\[[^\]]+\])?\{)[^}]+(?=\})/,
            lookbehind: !0
          },
          url: {
            pattern: /(\\url\{)[^}]+(?=\})/,
            lookbehind: !0
          },
          headline: {
            pattern: /(\\(?:part|chapter|section|subsection|frametitle|subsubsection|paragraph|subparagraph|subsubparagraph|subsubsubparagraph)\*?(?:\[[^\]]+\])?\{)[^}]+(?=\})/,
            lookbehind: !0,
            alias: 'class-name'
          },
          function : {
            pattern: t,
            alias: 'selector'
          },
          punctuation: /[[\]{}&]/
        },
        e.languages.tex = e.languages.latex,
        e.languages.context = e.languages.latex
      }(d),
      d.languages.less = d.languages.extend('css', {
        comment: [
          /\/\*[\s\S]*?\*\//,
          {
            pattern: /(^|[^\\])\/\/.*/,
            lookbehind: !0
          }
        ],
        atrule: {
          pattern: /@[\w-](?:\((?:[^(){}]|\([^(){}]*\))*\)|[^(){};\s]|\s+(?!\s))*?(?=\s*\{)/,
          inside: {
            punctuation: /[:()]/
          }
        },
        selector: {
          pattern: /(?:@\{[\w-]+\}|[^{};\s@])(?:@\{[\w-]+\}|\((?:[^(){}]|\([^(){}]*\))*\)|[^(){};@\s]|\s+(?!\s))*?(?=\s*\{)/,
          inside: {
            variable: /@+[\w-]+/
          }
        },
        property: /(?:@\{[\w-]+\}|[\w-])+(?:\+_?)?(?=\s*:)/i,
        operator: /[+\-*\/]/
      }),
      d.languages.insertBefore('less', 'property', {
        variable: [
          {
            pattern: /@[\w-]+\s*:/,
            inside: {
              punctuation: /:/
            }
          },
          /@@?[\w-]+/
        ],
        'mixin-usage': {
          pattern: /([{;]\s*)[.#](?!\d)[\w-].*?(?=[(;])/,
          lookbehind: !0,
          alias: 'function'
        }
      }),
      d.languages.llvm = {
        comment: /;.*/,
        string: {
          pattern: /"[^"]*"/,
          greedy: !0
        },
        boolean: /\b(?:true|false)\b/,
        variable: /[%@!#](?:(?!\d)(?:[-$.\w]|\\[a-f\d]{2})+|\d+)/i,
        label: /(?!\d)(?:[-$.\w]|\\[a-f\d]{2})+:/i,
        type: {
          pattern: /\b(?:double|float|fp128|half|i[1-9]\d*|label|metadata|ppc_fp128|token|void|x86_fp80|x86_mmx)\b/,
          alias: 'class-name'
        },
        keyword: /\b[a-z_][a-z_0-9]*\b/,
        number: /[+-]?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|\b0x[\dA-Fa-f]+\b|\b0xK[\dA-Fa-f]{20}\b|\b0x[ML][\dA-Fa-f]{32}\b|\b0xH[\dA-Fa-f]{4}\b/,
        punctuation: /[{}[\];(),.!*=<>]/
      },
      d.languages.makefile = {
        comment: {
          pattern: /(^|[^\\])#(?:\\(?:\r\n|[\s\S])|[^\\\r\n])*/,
          lookbehind: !0
        },
        string: {
          pattern: /(["'])(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/,
          greedy: !0
        },
        builtin: /\.[A-Z][^:#=\s]+(?=\s*:(?!=))/,
        symbol: {
          pattern: /^(?:[^:=\s]|[ \t]+(?![\s:]))+(?=\s*:(?!=))/m,
          inside: {
            variable: /\$+(?:(?!\$)[^(){}:#=\s]+|(?=[({]))/
          }
        },
        variable: /\$+(?:(?!\$)[^(){}:#=\s]+|\([@*%<^+?][DF]\)|(?=[({]))/,
        keyword: [
          /-include\b|\b(?:define|else|endef|endif|export|ifn?def|ifn?eq|include|override|private|sinclude|undefine|unexport|vpath)\b/,
          {
            pattern: /(\()(?:addsuffix|abspath|and|basename|call|dir|error|eval|file|filter(?:-out)?|findstring|firstword|flavor|foreach|guile|if|info|join|lastword|load|notdir|or|origin|patsubst|realpath|shell|sort|strip|subst|suffix|value|warning|wildcard|word(?:s|list)?)(?=[ \t])/,
            lookbehind: !0
          }
        ],
        operator: /(?:::|[?:+!])?=|[|@]/,
        punctuation: /[:;(){}]/
      },
      function (e) {
        function t(e) {
          return e = e.replace(/<inner>/g, (function () {
            return '(?:\\\\.|[^\\\\\n\r]|(?:\n|\r\n?)(?![\r\n]))'
          })),
          RegExp('((?:^|[^\\\\])(?:\\\\{2})*)(?:' + e + ')')
        }
        var n = '(?:\\\\.|``(?:[^`\r\n]|`(?!`))+``|`[^`\r\n]+`|[^\\\\|\r\n`])+',
        a = '\\|?__(?:\\|__)+\\|?(?:(?:\n|\r\n?)|(?![^]))'.replace(/__/g, (function () {
          return n
        })),
        r = '\\|?[ \t]*:?-{3,}:?[ \t]*(?:\\|[ \t]*:?-{3,}:?[ \t]*)+\\|?(?:\n|\r\n?)';
        e.languages.markdown = e.languages.extend('markup', {
        }),
        e.languages.insertBefore('markdown', 'prolog', {
          'front-matter-block': {
            pattern: /(^(?:\s*[\r\n])?)---(?!.)[\s\S]*?[\r\n]---(?!.)/,
            lookbehind: !0,
            greedy: !0,
            inside: {
              punctuation: /^---|---$/,
              'font-matter': {
                pattern: /\S+(?:\s+\S+)*/,
                alias: [
                  'yaml',
                  'language-yaml'
                ],
                inside: e.languages.yaml
              }
            }
          },
          blockquote: {
            pattern: /^>(?:[\t ]*>)*/m,
            alias: 'punctuation'
          },
          table: {
            pattern: RegExp('^' + a + r + '(?:' + a + ')*', 'm'),
            inside: {
              'table-data-rows': {
                pattern: RegExp('^(' + a + r + ')(?:' + a + ')*$'),
                lookbehind: !0,
                inside: {
                  'table-data': {
                    pattern: RegExp(n),
                    inside: e.languages.markdown
                  },
                  punctuation: /\|/
                }
              },
              'table-line': {
                pattern: RegExp('^(' + a + ')' + r + '$'),
                lookbehind: !0,
                inside: {
                  punctuation: /\||:?-{3,}:?/
                }
              },
              'table-header-row': {
                pattern: RegExp('^' + a + '$'),
                inside: {
                  'table-header': {
                    pattern: RegExp(n),
                    alias: 'important',
                    inside: e.languages.markdown
                  },
                  punctuation: /\|/
                }
              }
            }
          },
          code: [
            {
              pattern: /((?:^|\n)[ \t]*\n|(?:^|\r\n?)[ \t]*\r\n?)(?: {4}|\t).+(?:(?:\n|\r\n?)(?: {4}|\t).+)*/,
              lookbehind: !0,
              alias: 'keyword'
            },
            {
              pattern: /^```[\s\S]*?^```$/m,
              greedy: !0,
              inside: {
                'code-block': {
                  pattern: /^(```.*(?:\n|\r\n?))[\s\S]+?(?=(?:\n|\r\n?)^```$)/m,
                  lookbehind: !0
                },
                'code-language': {
                  pattern: /^(```).+/,
                  lookbehind: !0
                },
                punctuation: /```/
              }
            }
          ],
          title: [
            {
              pattern: /\S.*(?:\n|\r\n?)(?:==+|--+)(?=[ \t]*$)/m,
              alias: 'important',
              inside: {
                punctuation: /==+$|--+$/
              }
            },
            {
              pattern: /(^\s*)#.+/m,
              lookbehind: !0,
              alias: 'important',
              inside: {
                punctuation: /^#+|#+$/
              }
            }
          ],
          hr: {
            pattern: /(^\s*)([*-])(?:[\t ]*\2){2,}(?=\s*$)/m,
            lookbehind: !0,
            alias: 'punctuation'
          },
          list: {
            pattern: /(^\s*)(?:[*+-]|\d+\.)(?=[\t ].)/m,
            lookbehind: !0,
            alias: 'punctuation'
          },
          'url-reference': {
            pattern: /!?\[[^\]]+\]:[\t ]+(?:\S+|<(?:\\.|[^>\\])+>)(?:[\t ]+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\((?:\\.|[^)\\])*\)))?/,
            inside: {
              variable: {
                pattern: /^(!?\[)[^\]]+/,
                lookbehind: !0
              },
              string: /(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\((?:\\.|[^)\\])*\))$/,
              punctuation: /^[\[\]!:]|[<>]/
            },
            alias: 'url'
          },
          bold: {
            pattern: t('\\b__(?:(?!_)<inner>|_(?:(?!_)<inner>)+_)+__\\b|\\*\\*(?:(?!\\*)<inner>|\\*(?:(?!\\*)<inner>)+\\*)+\\*\\*'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              content: {
                pattern: /(^..)[\s\S]+(?=..$)/,
                lookbehind: !0,
                inside: {
                }
              },
              punctuation: /\*\*|__/
            }
          },
          italic: {
            pattern: t('\\b_(?:(?!_)<inner>|__(?:(?!_)<inner>)+__)+_\\b|\\*(?:(?!\\*)<inner>|\\*\\*(?:(?!\\*)<inner>)+\\*\\*)+\\*'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              content: {
                pattern: /(^.)[\s\S]+(?=.$)/,
                lookbehind: !0,
                inside: {
                }
              },
              punctuation: /[*_]/
            }
          },
          strike: {
            pattern: t('(~~?)(?:(?!~)<inner>)+\\2'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              content: {
                pattern: /(^~~?)[\s\S]+(?=\1$)/,
                lookbehind: !0,
                inside: {
                }
              },
              punctuation: /~~?/
            }
          },
          'code-snippet': {
            pattern: /(^|[^\\`])(?:``[^`\r\n]+(?:`[^`\r\n]+)*``(?!`)|`[^`\r\n]+`(?!`))/,
            lookbehind: !0,
            greedy: !0,
            alias: [
              'code',
              'keyword'
            ]
          },
          url: {
            pattern: t('!?\\[(?:(?!\\])<inner>)+\\](?:\\([^\\s)]+(?:[\t ]+"(?:\\\\.|[^"\\\\])*")?\\)|[ \t]?\\[(?:(?!\\])<inner>)+\\])'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              operator: /^!/,
              content: {
                pattern: /(^\[)[^\]]+(?=\])/,
                lookbehind: !0,
                inside: {
                }
              },
              variable: {
                pattern: /(^\][ \t]?\[)[^\]]+(?=\]$)/,
                lookbehind: !0
              },
              url: {
                pattern: /(^\]\()[^\s)]+/,
                lookbehind: !0
              },
              string: {
                pattern: /(^[ \t]+)"(?:\\.|[^"\\])*"(?=\)$)/,
                lookbehind: !0
              }
            }
          }
        }),
        [
          'url',
          'bold',
          'italic',
          'strike'
        ].forEach((function (t) {
          [
            'url',
            'bold',
            'italic',
            'strike',
            'code-snippet'
          ].forEach((function (n) {
            t !== n && (e.languages.markdown[t].inside.content.inside[n] = e.languages.markdown[n])
          }))
        })),
        e.hooks.add('after-tokenize', (function (e) {
          'markdown' !== e.language && 'md' !== e.language || function e(t) {
            if (t && 'string' != typeof t) for (var n = 0, a = t.length; n < a; n++) {
              var r = t[n];
              if ('code' === r.type) {
                var i = r.content[1],
                o = r.content[3];
                if (i && o && 'code-language' === i.type && 'code-block' === o.type && 'string' == typeof i.content) {
                  var s = i.content.replace(/\b#/g, 'sharp').replace(/\b\+\+/g, 'pp'),
                  l = 'language-' + (s = (/[a-z][\w-]*/i.exec(s) || [
                    ''
                  ]) [0].toLowerCase());
                  o.alias ? 'string' == typeof o.alias ? o.alias = [
                    o.alias,
                    l
                  ] : o.alias.push(l) : o.alias = [
                    l
                  ]
                }
              } else e(r.content)
            }
          }(e.tokens)
        })),
        e.hooks.add('wrap', (function (t) {
          if ('code-block' === t.type) {
            for (var n = '', a = 0, r = t.classes.length; a < r; a++) {
              var l = t.classes[a],
              d = /language-(.+)/.exec(l);
              if (d) {
                n = d[1];
                break
              }
            }
            var u = e.languages[n];
            if (u) t.content = e.highlight(function (e) {
              var t = e.replace(i, '');
              return t.replace(/&(\w{1,8}|#x?[\da-f]{1,8});/gi, (function (e, t) {
                var n;
                return '#' === (t = t.toLowerCase()) [0] ? (n = 'x' === t[1] ? parseInt(t.slice(2), 16) : Number(t.slice(1)), s(n)) : o[t] || e
              }))
            }(t.content), u, n);
             else if (n && 'none' !== n && e.plugins.autoloader) {
              var c = 'md-' + (new Date).valueOf() + '-' + Math.floor(10000000000000000 * Math.random());
              t.attributes.id = c,
              e.plugins.autoloader.loadLanguages(n, (function () {
                var t = document.getElementById(c);
                t && (t.innerHTML = e.highlight(t.textContent, e.languages[n], n))
              }))
            }
          }
        }));
        var i = RegExp(e.languages.markup.tag.pattern.source, 'gi'),
        o = {
          amp: '&',
          lt: '<',
          gt: '>',
          quot: '"'
        },
        s = String.fromCodePoint || String.fromCharCode;
        e.languages.md = e.languages.markdown
      }(d),
      d.languages.nasm = {
        comment: /;.*$/m,
        string: /(["'`])(?:\\.|(?!\1)[^\\\r\n])*\1/,
        label: {
          pattern: /(^\s*)[A-Za-z._?$][\w.?$@~#]*:/m,
          lookbehind: !0,
          alias: 'function'
        },
        keyword: [
          /\[?BITS (?:16|32|64)\]?/,
          {
            pattern: /(^\s*)section\s*[a-z.]+:?/im,
            lookbehind: !0
          },
          /(?:extern|global)[^;\r\n]*/i,
          /(?:CPU|FLOAT|DEFAULT).*$/m
        ],
        register: {
          pattern: /\b(?:st\d|[xyz]mm\d\d?|[cdt]r\d|r\d\d?[bwd]?|[er]?[abcd]x|[abcd][hl]|[er]?(?:bp|sp|si|di)|[cdefgs]s)\b/i,
          alias: 'variable'
        },
        number: /(?:\b|(?=\$))(?:0[hx](?:\.[\da-f]+|[\da-f]+(?:\.[\da-f]+)?)(?:p[+-]?\d+)?|\d[\da-f]+[hx]|\$\d[\da-f]*|0[oq][0-7]+|[0-7]+[oq]|0[by][01]+|[01]+[by]|0[dt]\d+|(?:\d+(?:\.\d+)?|\.\d+)(?:\.?e[+-]?\d+)?[dt]?)\b/i,
        operator: /[\[\]*+\-\/%<>=&|$!]/
      },
      d.languages.objectivec = d.languages.extend('c', {
        string: /("|')(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1|@"(?:\\(?:\r\n|[\s\S])|[^"\\\r\n])*"/,
        keyword: /\b(?:asm|typeof|inline|auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|int|long|register|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while|in|self|super)\b|(?:@interface|@end|@implementation|@protocol|@class|@public|@protected|@private|@property|@try|@catch|@finally|@throw|@synthesize|@dynamic|@selector)\b/,
        operator: /-[->]?|\+\+?|!=?|<<?=?|>>?=?|==?|&&?|\|\|?|[~^%?*\/@]/
      }),
      delete d.languages.objectivec['class-name'],
      d.languages.objc = d.languages.objectivec,
      d.languages.ocaml = {
        comment: /\(\*[\s\S]*?\*\)/,
        string: [
          {
            pattern: /"(?:\\.|[^\\\r\n"])*"/,
            greedy: !0
          },
          {
            pattern: /(['`])(?:\\(?:\d+|x[\da-f]+|.)|(?!\1)[^\\\r\n])\1/i,
            greedy: !0
          }
        ],
        number: /\b(?:0x[\da-f][\da-f_]+|(?:0[bo])?\d[\d_]*(?:\.[\d_]*)?(?:e[+-]?[\d_]+)?)/i,
        directive: {
          pattern: /\B#\w+/,
          alias: 'important'
        },
        label: {
          pattern: /\B~\w+/,
          alias: 'function'
        },
        'type-variable': {
          pattern: /\B'\w+/,
          alias: 'function'
        },
        variant: {
          pattern: /`\w+/,
          alias: 'variable'
        },
        module: {
          pattern: /\b[A-Z]\w+/,
          alias: 'variable'
        },
        keyword: /\b(?:as|assert|begin|class|constraint|do|done|downto|else|end|exception|external|for|fun|function|functor|if|in|include|inherit|initializer|lazy|let|match|method|module|mutable|new|nonrec|object|of|open|private|rec|sig|struct|then|to|try|type|val|value|virtual|when|where|while|with)\b/,
        boolean: /\b(?:false|true)\b/,
        operator: /:=|[=<>@^|&+\-*\/$%!?~][!$%&*+\-.\/:<=>?@^|~]*|\b(?:and|asr|land|lor|lsl|lsr|lxor|mod|or)\b/,
        punctuation: /[(){}\[\]|.,:;]|\b_\b/
      },
      d.languages.perl = {
        comment: [
          {
            pattern: /(^\s*)=\w[\s\S]*?=cut.*/m,
            lookbehind: !0
          },
          {
            pattern: /(^|[^\\$])#.*/,
            lookbehind: !0
          }
        ],
        string: [
          {
            pattern: /\b(?:q|qq|qx|qw)\s*([^a-zA-Z0-9\s{(\[<])(?:(?!\1)[^\\]|\\[\s\S])*\1/,
            greedy: !0
          },
          {
            pattern: /\b(?:q|qq|qx|qw)\s+([a-zA-Z0-9])(?:(?!\1)[^\\]|\\[\s\S])*\1/,
            greedy: !0
          },
          {
            pattern: /\b(?:q|qq|qx|qw)\s*\((?:[^()\\]|\\[\s\S])*\)/,
            greedy: !0
          },
          {
            pattern: /\b(?:q|qq|qx|qw)\s*\{(?:[^{}\\]|\\[\s\S])*\}/,
            greedy: !0
          },
          {
            pattern: /\b(?:q|qq|qx|qw)\s*\[(?:[^[\]\\]|\\[\s\S])*\]/,
            greedy: !0
          },
          {
            pattern: /\b(?:q|qq|qx|qw)\s*<(?:[^<>\\]|\\[\s\S])*>/,
            greedy: !0
          },
          {
            pattern: /("|`)(?:(?!\1)[^\\]|\\[\s\S])*\1/,
            greedy: !0
          },
          {
            pattern: /'(?:[^'\\\r\n]|\\.)*'/,
            greedy: !0
          }
        ],
        regex: [
          {
            pattern: /\b(?:m|qr)\s*([^a-zA-Z0-9\s{(\[<])(?:(?!\1)[^\\]|\\[\s\S])*\1[msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /\b(?:m|qr)\s+([a-zA-Z0-9])(?:(?!\1)[^\\]|\\[\s\S])*\1[msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /\b(?:m|qr)\s*\((?:[^()\\]|\\[\s\S])*\)[msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /\b(?:m|qr)\s*\{(?:[^{}\\]|\\[\s\S])*\}[msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /\b(?:m|qr)\s*\[(?:[^[\]\\]|\\[\s\S])*\][msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /\b(?:m|qr)\s*<(?:[^<>\\]|\\[\s\S])*>[msixpodualngc]*/,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s*([^a-zA-Z0-9\s{(\[<])(?:(?!\2)[^\\]|\\[\s\S])*\2(?:(?!\2)[^\\]|\\[\s\S])*\2[msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s+([a-zA-Z0-9])(?:(?!\2)[^\\]|\\[\s\S])*\2(?:(?!\2)[^\\]|\\[\s\S])*\2[msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s*\((?:[^()\\]|\\[\s\S])*\)\s*\((?:[^()\\]|\\[\s\S])*\)[msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s*\{(?:[^{}\\]|\\[\s\S])*\}\s*\{(?:[^{}\\]|\\[\s\S])*\}[msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s*\[(?:[^[\]\\]|\\[\s\S])*\]\s*\[(?:[^[\]\\]|\\[\s\S])*\][msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /(^|[^-]\b)(?:s|tr|y)\s*<(?:[^<>\\]|\\[\s\S])*>\s*<(?:[^<>\\]|\\[\s\S])*>[msixpodualngcer]*/,
            lookbehind: !0,
            greedy: !0
          },
          {
            pattern: /\/(?:[^\/\\\r\n]|\\.)*\/[msixpodualngc]*(?=\s*(?:$|[\r\n,.;})&|\-+*~<>!?^]|(?:lt|gt|le|ge|eq|ne|cmp|not|and|or|xor|x)\b))/,
            greedy: !0
          }
        ],
        variable: [
          /[&*$@%]\{\^[A-Z]+\}/,
          /[&*$@%]\^[A-Z_]/,
          /[&*$@%]#?(?=\{)/,
          /[&*$@%]#?(?:(?:::)*'?(?!\d)[\w$]+(?![\w$]))+(?:::)*/i,
          /[&*$@%]\d+/,
          /(?!%=)[$@%][!"#$%&'()*+,\-.\/:;<=>?@[\\\]^_`{|}~]/
        ],
        filehandle: {
          pattern: /<(?![<=])\S*>|\b_\b/,
          alias: 'symbol'
        },
        vstring: {
          pattern: /v\d+(?:\.\d+)*|\d+(?:\.\d+){2,}/,
          alias: 'string'
        },
        function : {
          pattern: /sub \w+/i,
          inside: {
            keyword: /sub/
          }
        },
        keyword: /\b(?:any|break|continue|default|delete|die|do|else|elsif|eval|for|foreach|given|goto|if|last|local|my|next|our|package|print|redo|require|return|say|state|sub|switch|undef|unless|until|use|when|while)\b/,
        number: /\b(?:0x[\dA-Fa-f](?:_?[\dA-Fa-f])*|0b[01](?:_?[01])*|(?:(?:\d(?:_?\d)*)?\.)?\d(?:_?\d)*(?:[Ee][+-]?\d+)?)\b/,
        operator: /-[rwxoRWXOezsfdlpSbctugkTBMAC]\b|\+[+=]?|-[-=>]?|\*\*?=?|\/\/?=?|=[=~>]?|~[~=]?|\|\|?=?|&&?=?|<(?:=>?|<=?)?|>>?=?|![~=]?|[%^]=?|\.(?:=|\.\.?)?|[\\?]|\bx(?:=|\b)|\b(?:lt|gt|le|ge|eq|ne|cmp|not|and|or|xor)\b/,
        punctuation: /[{}[\];(),:]/
      },
      function (e) {
        var t = /\/\*[\s\S]*?\*\/|\/\/.*|#(?!\[).*/,
        n = [
          {
            pattern: /\b(?:false|true)\b/i,
            alias: 'boolean'
          },
          {
            pattern: /(::\s*)\b[a-z_]\w*\b(?!\s*\()/i,
            greedy: !0,
            lookbehind: !0
          },
          {
            pattern: /(\b(?:case|const)\s+)\b[a-z_]\w*(?=\s*[;=])/i,
            greedy: !0,
            lookbehind: !0
          },
          /\b(?:null)\b/i,
          /\b[A-Z_][A-Z0-9_]*\b(?!\s*\()/
        ],
        a = /\b0b[01]+(?:_[01]+)*\b|\b0o[0-7]+(?:_[0-7]+)*\b|\b0x[\da-f]+(?:_[\da-f]+)*\b|(?:\b\d+(?:_\d+)*\.?(?:\d+(?:_\d+)*)?|\B\.\d+)(?:e[+-]?\d+)?/i,
        r = /<?=>|\?\?=?|\.{3}|\??->|[!=]=?=?|::|\*\*=?|--|\+\+|&&|\|\||<<|>>|[?~]|[/^|%*&<>.+-]=?/,
        i = /[{}\[\](),:;]/;
        e.languages.php = {
          delimiter: {
            pattern: /\?>$|^<\?(?:php(?=\s)|=)?/i,
            alias: 'important'
          },
          comment: t,
          variable: /\$+(?:\w+\b|(?=\{))/i,
          package: {
            pattern: /(namespace\s+|use\s+(?:function\s+)?)(?:\\?\b[a-z_]\w*)+\b(?!\\)/i,
            lookbehind: !0,
            inside: {
              punctuation: /\\/
            }
          },
          'class-name-definition': {
            pattern: /(\b(?:class|enum|interface|trait)\s+)\b[a-z_]\w*(?!\\)\b/i,
            lookbehind: !0,
            alias: 'class-name'
          },
          'function-definition': {
            pattern: /(\bfunction\s+)[a-z_]\w*(?=\s*\()/i,
            lookbehind: !0,
            alias: 'function'
          },
          keyword: [
            {
              pattern: /(\(\s*)\b(?:bool|boolean|int|integer|float|string|object|array)\b(?=\s*\))/i,
              alias: 'type-casting',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /([(,?]\s*)\b(?:bool|int|float|string|object|array(?!\s*\()|mixed|self|static|callable|iterable|(?:null|false)(?=\s*\|))\b(?=\s*\$)/i,
              alias: 'type-hint',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /([(,?]\s*[\w|]\|\s*)(?:null|false)\b(?=\s*\$)/i,
              alias: 'type-hint',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /(\)\s*:\s*(?:\?\s*)?)\b(?:bool|int|float|string|object|void|array(?!\s*\()|mixed|self|static|callable|iterable|(?:null|false)(?=\s*\|))\b/i,
              alias: 'return-type',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /(\)\s*:\s*(?:\?\s*)?[\w|]\|\s*)(?:null|false)\b/i,
              alias: 'return-type',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /\b(?:bool|int|float|string|object|void|array(?!\s*\()|mixed|iterable|(?:null|false)(?=\s*\|))\b/i,
              alias: 'type-declaration',
              greedy: !0
            },
            {
              pattern: /(\|\s*)(?:null|false)\b/i,
              alias: 'type-declaration',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /\b(?:parent|self|static)(?=\s*::)/i,
              alias: 'static-context',
              greedy: !0
            },
            {
              pattern: /(\byield\s+)from\b/i,
              lookbehind: !0
            },
            /\bclass\b/i,
            {
              pattern: /((?:^|[^\s>:]|(?:^|[^-])>|(?:^|[^:]):)\s*)\b(?:__halt_compiler|abstract|and|array|as|break|callable|case|catch|clone|const|continue|declare|default|die|do|echo|else|elseif|empty|enddeclare|endfor|endforeach|endif|endswitch|endwhile|enum|eval|exit|extends|final|finally|fn|for|foreach|function|global|goto|if|implements|include|include_once|instanceof|insteadof|interface|isset|list|namespace|match|new|or|parent|print|private|protected|public|require|require_once|return|self|static|switch|throw|trait|try|unset|use|var|while|xor|yield)\b/i,
              lookbehind: !0
            }
          ],
          'argument-name': {
            pattern: /([(,]\s+)\b[a-z_]\w*(?=\s*:(?!:))/i,
            lookbehind: !0
          },
          'class-name': [
            {
              pattern: /(\b(?:extends|implements|instanceof|new(?!\s+self|\s+static))\s+|\bcatch\s*\()\b[a-z_]\w*(?!\\)\b/i,
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /(\|\s*)\b[a-z_]\w*(?!\\)\b/i,
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /\b[a-z_]\w*(?!\\)\b(?=\s*\|)/i,
              greedy: !0
            },
            {
              pattern: /(\|\s*)(?:\\?\b[a-z_]\w*)+\b/i,
              alias: 'class-name-fully-qualified',
              greedy: !0,
              lookbehind: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /(?:\\?\b[a-z_]\w*)+\b(?=\s*\|)/i,
              alias: 'class-name-fully-qualified',
              greedy: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /(\b(?:extends|implements|instanceof|new(?!\s+self\b|\s+static\b))\s+|\bcatch\s*\()(?:\\?\b[a-z_]\w*)+\b(?!\\)/i,
              alias: 'class-name-fully-qualified',
              greedy: !0,
              lookbehind: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /\b[a-z_]\w*(?=\s*\$)/i,
              alias: 'type-declaration',
              greedy: !0
            },
            {
              pattern: /(?:\\?\b[a-z_]\w*)+(?=\s*\$)/i,
              alias: [
                'class-name-fully-qualified',
                'type-declaration'
              ],
              greedy: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /\b[a-z_]\w*(?=\s*::)/i,
              alias: 'static-context',
              greedy: !0
            },
            {
              pattern: /(?:\\?\b[a-z_]\w*)+(?=\s*::)/i,
              alias: [
                'class-name-fully-qualified',
                'static-context'
              ],
              greedy: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /([(,?]\s*)[a-z_]\w*(?=\s*\$)/i,
              alias: 'type-hint',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /([(,?]\s*)(?:\\?\b[a-z_]\w*)+(?=\s*\$)/i,
              alias: [
                'class-name-fully-qualified',
                'type-hint'
              ],
              greedy: !0,
              lookbehind: !0,
              inside: {
                punctuation: /\\/
              }
            },
            {
              pattern: /(\)\s*:\s*(?:\?\s*)?)\b[a-z_]\w*(?!\\)\b/i,
              alias: 'return-type',
              greedy: !0,
              lookbehind: !0
            },
            {
              pattern: /(\)\s*:\s*(?:\?\s*)?)(?:\\?\b[a-z_]\w*)+\b(?!\\)/i,
              alias: [
                'class-name-fully-qualified',
                'return-type'
              ],
              greedy: !0,
              lookbehind: !0,
              inside: {
                punctuation: /\\/
              }
            }
          ],
          constant: n,
          function : {
            pattern: /(^|[^\\\w])\\?[a-z_](?:[\w\\]*\w)?(?=\s*\()/i,
            lookbehind: !0,
            inside: {
              punctuation: /\\/
            }
          },
          property: {
            pattern: /(->\s*)\w+/,
            lookbehind: !0
          },
          number: a,
          operator: r,
          punctuation: i
        };
        var o = {
          pattern: /\{\$(?:\{(?:\{[^{}]+\}|[^{}]+)\}|[^{}])+\}|(^|[^\\{])\$+(?:\w+(?:\[[^\r\n\[\]]+\]|->\w+)?)/,
          lookbehind: !0,
          inside: e.languages.php
        },
        s = [
          {
            pattern: /<<<'([^']+)'[\r\n](?:.*[\r\n])*?\1;/,
            alias: 'nowdoc-string',
            greedy: !0,
            inside: {
              delimiter: {
                pattern: /^<<<'[^']+'|[a-z_]\w*;$/i,
                alias: 'symbol',
                inside: {
                  punctuation: /^<<<'?|[';]$/
                }
              }
            }
          },
          {
            pattern: /<<<(?:"([^"]+)"[\r\n](?:.*[\r\n])*?\1;|([a-z_]\w*)[\r\n](?:.*[\r\n])*?\2;)/i,
            alias: 'heredoc-string',
            greedy: !0,
            inside: {
              delimiter: {
                pattern: /^<<<(?:"[^"]+"|[a-z_]\w*)|[a-z_]\w*;$/i,
                alias: 'symbol',
                inside: {
                  punctuation: /^<<<"?|[";]$/
                }
              },
              interpolation: o
            }
          },
          {
            pattern: /`(?:\\[\s\S]|[^\\`])*`/,
            alias: 'backtick-quoted-string',
            greedy: !0
          },
          {
            pattern: /'(?:\\[\s\S]|[^\\'])*'/,
            alias: 'single-quoted-string',
            greedy: !0
          },
          {
            pattern: /"(?:\\[\s\S]|[^\\"])*"/,
            alias: 'double-quoted-string',
            greedy: !0,
            inside: {
              interpolation: o
            }
          }
        ];
        e.languages.insertBefore('php', 'variable', {
          string: s,
          attribute: {
            pattern: /#\[(?:[^"'\/#]|\/(?![*/])|\/\/.*$|#(?!\[).*$|\/\*(?:[^*]|\*(?!\/))*\*\/|"(?:\\[\s\S]|[^\\"])*"|'(?:\\[\s\S]|[^\\'])*')+\](?=\s*[a-z$#])/im,
            greedy: !0,
            inside: {
              'attribute-content': {
                pattern: /^(#\[)[\s\S]+(?=\]$)/,
                lookbehind: !0,
                inside: {
                  comment: t,
                  string: s,
                  'attribute-class-name': [
                    {
                      pattern: /([^:]|^)\b[a-z_]\w*(?!\\)\b/i,
                      alias: 'class-name',
                      greedy: !0,
                      lookbehind: !0
                    },
                    {
                      pattern: /([^:]|^)(?:\\?\b[a-z_]\w*)+/i,
                      alias: [
                        'class-name',
                        'class-name-fully-qualified'
                      ],
                      greedy: !0,
                      lookbehind: !0,
                      inside: {
                        punctuation: /\\/
                      }
                    }
                  ],
                  constant: n,
                  number: a,
                  operator: r,
                  punctuation: i
                }
              },
              delimiter: {
                pattern: /^#\[|\]$/,
                alias: 'punctuation'
              }
            }
          }
        }),
        e.hooks.add('before-tokenize', (function (t) {
          /<\?/.test(t.code) && e.languages['markup-templating'].buildPlaceholders(t, 'php', /<\?(?:[^"'/#]|\/(?![*/])|("|')(?:\\[\s\S]|(?!\1)[^\\])*\1|(?:\/\/|#(?!\[))(?:[^?\n\r]|\?(?!>))*(?=$|\?>|[\r\n])|#\[|\/\*(?:[^*]|\*(?!\/))*(?:\*\/|$))*?(?:\?>|$)/gi)
        })),
        e.hooks.add('after-tokenize', (function (t) {
          e.languages['markup-templating'].tokenizePlaceholders(t, 'php')
        }))
      }(d),
      d.languages.insertBefore('php', 'variable', {
        this: /\$this\b/,
        global: /\$(?:_(?:SERVER|GET|POST|FILES|REQUEST|SESSION|ENV|COOKIE)|GLOBALS|HTTP_RAW_POST_DATA|argc|argv|php_errormsg|http_response_header)\b/,
        scope: {
          pattern: /\b[\w\\]+::/,
          inside: {
            keyword: /static|self|parent/,
            punctuation: /::|\\/
          }
        }
      }),
      s = d.languages.powershell = {
        comment: [
          {
            pattern: /(^|[^`])<#[\s\S]*?#>/,
            lookbehind: !0
          },
          {
            pattern: /(^|[^`])#.*/,
            lookbehind: !0
          }
        ],
        string: [
          {
            pattern: /"(?:`[\s\S]|[^`"])*"/,
            greedy: !0,
            inside: {
              function : {
                pattern: /(^|[^`])\$\((?:\$\([^\r\n()]*\)|(?!\$\()[^\r\n)])*\)/,
                lookbehind: !0,
                inside: {
                }
              }
            }
          },
          {
            pattern: /'(?:[^']|'')*'/,
            greedy: !0
          }
        ],
        namespace: /\[[a-z](?:\[(?:\[[^\]]*\]|[^\[\]])*\]|[^\[\]])*\]/i,
        boolean: /\$(?:true|false)\b/i,
        variable: /\$\w+\b/,
        function : [
          /\b(?:Add|Approve|Assert|Backup|Block|Checkpoint|Clear|Close|Compare|Complete|Compress|Confirm|Connect|Convert|ConvertFrom|ConvertTo|Copy|Debug|Deny|Disable|Disconnect|Dismount|Edit|Enable|Enter|Exit|Expand|Export|Find|ForEach|Format|Get|Grant|Group|Hide|Import|Initialize|Install|Invoke|Join|Limit|Lock|Measure|Merge|Move|New|Open|Optimize|Out|Ping|Pop|Protect|Publish|Push|Read|Receive|Redo|Register|Remove|Rename|Repair|Request|Reset|Resize|Resolve|Restart|Restore|Resume|Revoke|Save|Search|Select|Send|Set|Show|Skip|Sort|Split|Start|Step|Stop|Submit|Suspend|Switch|Sync|Tee|Test|Trace|Unblock|Undo|Uninstall|Unlock|Unprotect|Unpublish|Unregister|Update|Use|Wait|Watch|Where|Write)-[a-z]+\b/i,
          /\b(?:ac|cat|chdir|clc|cli|clp|clv|compare|copy|cp|cpi|cpp|cvpa|dbp|del|diff|dir|ebp|echo|epal|epcsv|epsn|erase|fc|fl|ft|fw|gal|gbp|gc|gci|gcs|gdr|gi|gl|gm|gp|gps|group|gsv|gu|gv|gwmi|iex|ii|ipal|ipcsv|ipsn|irm|iwmi|iwr|kill|lp|ls|measure|mi|mount|move|mp|mv|nal|ndr|ni|nv|ogv|popd|ps|pushd|pwd|rbp|rd|rdr|ren|ri|rm|rmdir|rni|rnp|rp|rv|rvpa|rwmi|sal|saps|sasv|sbp|sc|select|set|shcm|si|sl|sleep|sls|sort|sp|spps|spsv|start|sv|swmi|tee|trcm|type|write)\b/i
        ],
        keyword: /\b(?:Begin|Break|Catch|Class|Continue|Data|Define|Do|DynamicParam|Else|ElseIf|End|Exit|Filter|Finally|For|ForEach|From|Function|If|InlineScript|Parallel|Param|Process|Return|Sequence|Switch|Throw|Trap|Try|Until|Using|Var|While|Workflow)\b/i,
        operator: {
          pattern: /(\W?)(?:!|-(?:eq|ne|gt|ge|lt|le|sh[lr]|not|b?(?:and|x?or)|(?:Not)?(?:Like|Match|Contains|In)|Replace|Join|is(?:Not)?|as)\b|-[-=]?|\+[+=]?|[*\/%]=?)/i,
          lookbehind: !0
        },
        punctuation: /[|{}[\];(),.]/
      },
      (l = s.string[0].inside).boolean = s.boolean,
      l.variable = s.variable,
      l.function.inside = s,
      d.languages.processing = d.languages.extend('clike', {
        keyword: /\b(?:break|catch|case|class|continue|default|else|extends|final|for|if|implements|import|new|null|private|public|return|static|super|switch|this|try|void|while)\b/,
        operator: /<[<=]?|>[>=]?|&&?|\|\|?|[%?]|[!=+\-*\/]=?/
      }),
      d.languages.insertBefore('processing', 'number', {
        constant: /\b(?!XML\b)[A-Z][A-Z\d_]+\b/,
        type: {
          pattern: /\b(?:boolean|byte|char|color|double|float|int|[A-Z]\w*)\b/,
          alias: 'variable'
        }
      }),
      d.languages.processing.function = /\b\w+(?=\s*\()/,
      d.languages.processing['class-name'].alias = 'variable',
      function (e) {
        e.languages.pug = {
          comment: {
            pattern: /(^([\t ]*))\/\/.*(?:(?:\r?\n|\r)\2[\t ].+)*/m,
            lookbehind: !0
          },
          'multiline-script': {
            pattern: /(^([\t ]*)script\b.*\.[\t ]*)(?:(?:\r?\n|\r(?!\n))(?:\2[\t ].+|\s*?(?=\r?\n|\r)))+/m,
            lookbehind: !0,
            inside: e.languages.javascript
          },
          filter: {
            pattern: /(^([\t ]*)):.+(?:(?:\r?\n|\r(?!\n))(?:\2[\t ].+|\s*?(?=\r?\n|\r)))+/m,
            lookbehind: !0,
            inside: {
              'filter-name': {
                pattern: /^:[\w-]+/,
                alias: 'variable'
              }
            }
          },
          'multiline-plain-text': {
            pattern: /(^([\t ]*)[\w\-#.]+\.[\t ]*)(?:(?:\r?\n|\r(?!\n))(?:\2[\t ].+|\s*?(?=\r?\n|\r)))+/m,
            lookbehind: !0
          },
          markup: {
            pattern: /(^[\t ]*)<.+/m,
            lookbehind: !0,
            inside: e.languages.markup
          },
          doctype: {
            pattern: /((?:^|\n)[\t ]*)doctype(?: .+)?/,
            lookbehind: !0
          },
          'flow-control': {
            pattern: /(^[\t ]*)(?:if|unless|else|case|when|default|each|while)\b(?: .+)?/m,
            lookbehind: !0,
            inside: {
              each: {
                pattern: /^each .+? in\b/,
                inside: {
                  keyword: /\b(?:each|in)\b/,
                  punctuation: /,/
                }
              },
              branch: {
                pattern: /^(?:if|unless|else|case|when|default|while)\b/,
                alias: 'keyword'
              },
              rest: e.languages.javascript
            }
          },
          keyword: {
            pattern: /(^[\t ]*)(?:block|extends|include|append|prepend)\b.+/m,
            lookbehind: !0
          },
          mixin: [
            {
              pattern: /(^[\t ]*)mixin .+/m,
              lookbehind: !0,
              inside: {
                keyword: /^mixin/,
                function : /\w+(?=\s*\(|\s*$)/,
                punctuation: /[(),.]/
              }
            },
            {
              pattern: /(^[\t ]*)\+.+/m,
              lookbehind: !0,
              inside: {
                name: {
                  pattern: /^\+\w+/,
                  alias: 'function'
                },
                rest: e.languages.javascript
              }
            }
          ],
          script: {
            pattern: /(^[\t ]*script(?:(?:&[^(]+)?\([^)]+\))*[\t ]).+/m,
            lookbehind: !0,
            inside: e.languages.javascript
          },
          'plain-text': {
            pattern: /(^[\t ]*(?!-)[\w\-#.]*[\w\-](?:(?:&[^(]+)?\([^)]+\))*\/?[\t ]).+/m,
            lookbehind: !0
          },
          tag: {
            pattern: /(^[\t ]*)(?!-)[\w\-#.]*[\w\-](?:(?:&[^(]+)?\([^)]+\))*\/?:?/m,
            lookbehind: !0,
            inside: {
              attributes: [
                {
                  pattern: /&[^(]+\([^)]+\)/,
                  inside: e.languages.javascript
                },
                {
                  pattern: /\([^)]+\)/,
                  inside: {
                    'attr-value': {
                      pattern: /(=\s*(?!\s))(?:\{[^}]*\}|[^,)\r\n]+)/,
                      lookbehind: !0,
                      inside: e.languages.javascript
                    },
                    'attr-name': /[\w-]+(?=\s*!?=|\s*[,)])/,
                    punctuation: /[!=(),]+/
                  }
                }
              ],
              punctuation: /:/,
              'attr-id': /#[\w\-]+/,
              'attr-class': /\.[\w\-]+/
            }
          },
          code: [
            {
              pattern: /(^[\t ]*(?:-|!?=)).+/m,
              lookbehind: !0,
              inside: e.languages.javascript
            }
          ],
          punctuation: /[.\-!=|]+/
        };
        for (var t = [
          {
            filter: 'atpl',
            language: 'twig'
          },
          {
            filter: 'coffee',
            language: 'coffeescript'
          },
          'ejs',
          'handlebars',
          'less',
          'livescript',
          'markdown',
          {
            filter: 'sass',
            language: 'scss'
          },
          'stylus'
        ], n = {
        }, a = 0, r = t.length; a < r; a++) {
          var i = t[a];
          i = 'string' == typeof i ? {
            filter: i,
            language: i
          }
           : i,
          e.languages[i.language] && (n['filter-' + i.filter] = {
            pattern: RegExp('(^([\t ]*)):<filter_name>(?:(?:\r?\n|\r(?!\n))(?:\\2[\t ].+|\\s*?(?=\r?\n|\r)))+'.replace('<filter_name>', (function () {
              return i.filter
            })), 'm'),
            lookbehind: !0,
            inside: {
              'filter-name': {
                pattern: /^:[\w-]+/,
                alias: 'variable'
              },
              rest: e.languages[i.language]
            }
          })
        }
        e.languages.insertBefore('pug', 'filter', n)
      }(d),
      d.languages.python = {
        comment: {
          pattern: /(^|[^\\])#.*/,
          lookbehind: !0
        },
        'string-interpolation': {
          pattern: /(?:f|rf|fr)(?:("""|''')[\s\S]*?\1|("|')(?:\\.|(?!\2)[^\\\r\n])*\2)/i,
          greedy: !0,
          inside: {
            interpolation: {
              pattern: /((?:^|[^{])(?:\{\{)*)\{(?!\{)(?:[^{}]|\{(?!\{)(?:[^{}]|\{(?!\{)(?:[^{}])+\})+\})+\}/,
              lookbehind: !0,
              inside: {
                'format-spec': {
                  pattern: /(:)[^:(){}]+(?=\}$)/,
                  lookbehind: !0
                },
                'conversion-option': {
                  pattern: /![sra](?=[:}]$)/,
                  alias: 'punctuation'
                },
                rest: null
              }
            },
            string: /[\s\S]+/
          }
        },
        'triple-quoted-string': {
          pattern: /(?:[rub]|rb|br)?("""|''')[\s\S]*?\1/i,
          greedy: !0,
          alias: 'string'
        },
        string: {
          pattern: /(?:[rub]|rb|br)?("|')(?:\\.|(?!\1)[^\\\r\n])*\1/i,
          greedy: !0
        },
        function : {
          pattern: /((?:^|\s)def[ \t]+)[a-zA-Z_]\w*(?=\s*\()/g,
          lookbehind: !0
        },
        'class-name': {
          pattern: /(\bclass\s+)\w+/i,
          lookbehind: !0
        },
        decorator: {
          pattern: /(^[\t ]*)@\w+(?:\.\w+)*/im,
          lookbehind: !0,
          alias: [
            'annotation',
            'punctuation'
          ],
          inside: {
            punctuation: /\./
          }
        },
        keyword: /\b(?:and|as|assert|async|await|break|class|continue|def|del|elif|else|except|exec|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|print|raise|return|try|while|with|yield)\b/,
        builtin: /\b(?:__import__|abs|all|any|apply|ascii|basestring|bin|bool|buffer|bytearray|bytes|callable|chr|classmethod|cmp|coerce|compile|complex|delattr|dict|dir|divmod|enumerate|eval|execfile|file|filter|float|format|frozenset|getattr|globals|hasattr|hash|help|hex|id|input|int|intern|isinstance|issubclass|iter|len|list|locals|long|map|max|memoryview|min|next|object|oct|open|ord|pow|property|range|raw_input|reduce|reload|repr|reversed|round|set|setattr|slice|sorted|staticmethod|str|sum|super|tuple|type|unichr|unicode|vars|xrange|zip)\b/,
        boolean: /\b(?:True|False|None)\b/,
        number: /\b0(?:b(?:_?[01])+|o(?:_?[0-7])+|x(?:_?[a-f0-9])+)\b|(?:\b\d+(?:_\d+)*(?:\.(?:\d+(?:_\d+)*)?)?|\B\.\d+(?:_\d+)*)(?:e[+-]?\d+(?:_\d+)*)?j?\b/i,
        operator: /[-+%=]=?|!=|\*\*?=?|\/\/?=?|<[<=>]?|>[=>]?|[&|^~]/,
        punctuation: /[{}[\];(),.:]/
      },
      d.languages.python['string-interpolation'].inside.interpolation.inside.rest = d.languages.python,
      d.languages.py = d.languages.python,
      d.languages.r = {
        comment: /#.*/,
        string: {
          pattern: /(['"])(?:\\.|(?!\1)[^\\\r\n])*\1/,
          greedy: !0
        },
        'percent-operator': {
          pattern: /%[^%\s]*%/,
          alias: 'operator'
        },
        boolean: /\b(?:TRUE|FALSE)\b/,
        ellipsis: /\.\.(?:\.|\d+)/,
        number: [
          /\b(?:NaN|Inf)\b/,
          /(?:\b0x[\dA-Fa-f]+(?:\.\d*)?|\b\d+(?:\.\d*)?|\B\.\d+)(?:[EePp][+-]?\d+)?[iL]?/
        ],
        keyword: /\b(?:if|else|repeat|while|function|for|in|next|break|NULL|NA|NA_integer_|NA_real_|NA_complex_|NA_character_)\b/,
        operator: /->?>?|<(?:=|<?-)?|[>=!]=?|::?|&&?|\|\|?|[+*\/^$@~]/,
        punctuation: /[(){}\[\],;]/
      },
      function (e) {
        var t = e.util.clone(e.languages.javascript),
        n = '(?:\\{<S>*\\.{3}(?:[^{}]|<BRACES>)*\\})';
        function a(e, t) {
          return e = e.replace(/<S>/g, (function () {
            return '(?:\\s|//.*(?!.)|/\\*(?:[^*]|\\*(?!/))\\*/)'
          })).replace(/<BRACES>/g, (function () {
            return '(?:\\{(?:\\{(?:\\{[^{}]*\\}|[^{}])*\\}|[^{}])*\\})'
          })).replace(/<SPREAD>/g, (function () {
            return n
          })),
          RegExp(e, t)
        }
        n = a(n).source,
        e.languages.jsx = e.languages.extend('markup', t),
        e.languages.jsx.tag.pattern = a('</?(?:[\\w.:-]+(?:<S>+(?:[\\w.:$-]+(?:=(?:"(?:\\\\[^]|[^\\\\"])*"|\'(?:\\\\[^]|[^\\\\\'])*\'|[^\\s{\'"/>=]+|<BRACES>))?|<SPREAD>))*<S>*/?)?>'),
        e.languages.jsx.tag.inside.tag.pattern = /^<\/?[^\s>\/]*/i,
        e.languages.jsx.tag.inside['attr-value'].pattern = /=(?!\{)(?:"(?:\\[\s\S]|[^\\"])*"|'(?:\\[\s\S]|[^\\'])*'|[^\s'">]+)/i,
        e.languages.jsx.tag.inside.tag.inside['class-name'] = /^[A-Z]\w*(?:\.[A-Z]\w*)*$/,
        e.languages.jsx.tag.inside.comment = t.comment,
        e.languages.insertBefore('inside', 'attr-name', {
          spread: {
            pattern: a('<SPREAD>'),
            inside: e.languages.jsx
          }
        }, e.languages.jsx.tag),
        e.languages.insertBefore('inside', 'special-attr', {
          script: {
            pattern: a('=<BRACES>'),
            inside: {
              'script-punctuation': {
                pattern: /^=(?=\{)/,
                alias: 'punctuation'
              },
              rest: e.languages.jsx
            },
            alias: 'language-javascript'
          }
        }, e.languages.jsx.tag);
        var r = function e(t) {
          return t ? 'string' == typeof t ? t : 'string' == typeof t.content ? t.content : t.content.map(e).join('') : ''
        },
        i = function t(n) {
          for (var a = [
          ], i = 0; i < n.length; i++) {
            var o = n[i],
            s = !1;
            if ('string' != typeof o && ('tag' === o.type && o.content[0] && 'tag' === o.content[0].type ? '</' === o.content[0].content[0].content ? 0 < a.length && a[a.length - 1].tagName === r(o.content[0].content[1]) && a.pop() : '/>' === o.content[o.content.length - 1].content || a.push({
              tagName: r(o.content[0].content[1]),
              openedBraces: 0
            }) : 0 < a.length && 'punctuation' === o.type && '{' === o.content ? a[a.length - 1].openedBraces++ : 0 < a.length && 0 < a[a.length - 1].openedBraces && 'punctuation' === o.type && '}' === o.content ? a[a.length - 1].openedBraces-- : s = !0), (s || 'string' == typeof o) && 0 < a.length && 0 === a[a.length - 1].openedBraces) {
              var l = r(o);
              i < n.length - 1 && ('string' == typeof n[i + 1] || 'plain-text' === n[i + 1].type) && (l += r(n[i + 1]), n.splice(i + 1, 1)),
              0 < i && ('string' == typeof n[i - 1] || 'plain-text' === n[i - 1].type) && (l = r(n[i - 1]) + l, n.splice(i - 1, 1), i--),
              n[i] = new e.Token('plain-text', l, null, l)
            }
            o.content && 'string' != typeof o.content && t(o.content)
          }
        };
        e.hooks.add('after-tokenize', (function (e) {
          'jsx' !== e.language && 'tsx' !== e.language || i(e.tokens)
        }))
      }(d),
      function (e) {
        e.languages.typescript = e.languages.extend('javascript', {
          'class-name': {
            pattern: /(\b(?:class|extends|implements|instanceof|interface|new|type)\s+)(?!keyof\b)(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?:\s*<(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*>)?/,
            lookbehind: !0,
            greedy: !0,
            inside: null
          },
          builtin: /\b(?:string|Function|any|number|boolean|Array|symbol|console|Promise|unknown|never)\b/
        }),
        e.languages.typescript.keyword.push(/\b(?:abstract|as|declare|implements|is|keyof|readonly|require)\b/, /\b(?:asserts|infer|interface|module|namespace|type)\b(?=\s*(?:[{_$a-zA-Z\xA0-\uFFFF]|$))/, /\btype\b(?=\s*(?:[\{*]|$))/),
        delete e.languages.typescript.parameter;
        var t = e.languages.extend('typescript', {
        });
        delete t['class-name'],
        e.languages.typescript['class-name'].inside = t,
        e.languages.insertBefore('typescript', 'function', {
          decorator: {
            pattern: /@[$\w\xA0-\uFFFF]+/,
            inside: {
              at: {
                pattern: /^@/,
                alias: 'operator'
              },
              function : /^[\s\S]+/
            }
          },
          'generic-function': {
            pattern: /#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*\s*<(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*>(?=\s*\()/,
            greedy: !0,
            inside: {
              function : /^#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*/,
              generic: {
                pattern: /<[\s\S]+/,
                alias: 'class-name',
                inside: t
              }
            }
          }
        }),
        e.languages.ts = e.languages.typescript
      }(d),
      function (e) {
        var t = e.util.clone(e.languages.typescript);
        e.languages.tsx = e.languages.extend('jsx', t);
        var n = e.languages.tsx.tag;
        n.pattern = RegExp('(^|[^\\w$]|(?=</))(?:' + n.pattern.source + ')', n.pattern.flags),
        n.lookbehind = !0
      }(d),
      d.languages.reason = d.languages.extend('clike', {
        string: {
          pattern: /"(?:\\(?:\r\n|[\s\S])|[^\\\r\n"])*"/,
          greedy: !0
        },
        'class-name': /\b[A-Z]\w*/,
        keyword: /\b(?:and|as|assert|begin|class|constraint|do|done|downto|else|end|exception|external|for|fun|function|functor|if|in|include|inherit|initializer|lazy|let|method|module|mutable|new|nonrec|object|of|open|or|private|rec|sig|struct|switch|then|to|try|type|val|virtual|when|while|with)\b/,
        operator: /\.{3}|:[:=]|\|>|->|=(?:==?|>)?|<=?|>=?|[|^?'#!~`]|[+\-*\/]\.?|\b(?:mod|land|lor|lxor|lsl|lsr|asr)\b/
      }),
      d.languages.insertBefore('reason', 'class-name', {
        character: {
          pattern: /'(?:\\x[\da-f]{2}|\\o[0-3][0-7][0-7]|\\\d{3}|\\.|[^'\\\r\n])'/,
          alias: 'string'
        },
        constructor: {
          pattern: /\b[A-Z]\w*\b(?!\s*\.)/,
          alias: 'variable'
        },
        label: {
          pattern: /\b[a-z]\w*(?=::)/,
          alias: 'symbol'
        }
      }),
      delete d.languages.reason.function,
      function (e) {
        for (var t = '/\\*(?:[^*/]|\\*(?!/)|/(?!\\*)|<self>)*\\*/', n = 0; n < 2; n++) t = t.replace(/<self>/g, (function () {
          return t
        }));
        t = t.replace(/<self>/g, (function () {
          return '[^\\s\\S]'
        })),
        e.languages.rust = {
          comment: [
            {
              pattern: RegExp('(^|[^\\\\])' + t),
              lookbehind: !0,
              greedy: !0
            },
            {
              pattern: /(^|[^\\:])\/\/.*/,
              lookbehind: !0,
              greedy: !0
            }
          ],
          string: {
            pattern: /b?"(?:\\[\s\S]|[^\\"])*"|b?r(#*)"(?:[^"]|"(?!\1))*"\1/,
            greedy: !0
          },
          char: {
            pattern: /b?'(?:\\(?:x[0-7][\da-fA-F]|u\{(?:[\da-fA-F]_*){1,6}\}|.)|[^\\\r\n\t'])'/,
            greedy: !0,
            alias: 'string'
          },
          attribute: {
            pattern: /#!?\[(?:[^\[\]"]|"(?:\\[\s\S]|[^\\"])*")*\]/,
            greedy: !0,
            alias: 'attr-name',
            inside: {
              string: null
            }
          },
          'closure-params': {
            pattern: /([=(,:]\s*|\bmove\s*)\|[^|]*\||\|[^|]*\|(?=\s*(?:\{|->))/,
            lookbehind: !0,
            greedy: !0,
            inside: {
              'closure-punctuation': {
                pattern: /^\||\|$/,
                alias: 'punctuation'
              },
              rest: null
            }
          },
          'lifetime-annotation': {
            pattern: /'\w+/,
            alias: 'symbol'
          },
          'fragment-specifier': {
            pattern: /(\$\w+:)[a-z]+/,
            lookbehind: !0,
            alias: 'punctuation'
          },
          variable: /\$\w+/,
          'function-definition': {
            pattern: /(\bfn\s+)\w+/,
            lookbehind: !0,
            alias: 'function'
          },
          'type-definition': {
            pattern: /(\b(?:enum|struct|union)\s+)\w+/,
            lookbehind: !0,
            alias: 'class-name'
          },
          'module-declaration': [
            {
              pattern: /(\b(?:crate|mod)\s+)[a-z][a-z_\d]*/,
              lookbehind: !0,
              alias: 'namespace'
            },
            {
              pattern: /(\b(?:crate|self|super)\s*)::\s*[a-z][a-z_\d]*\b(?:\s*::(?:\s*[a-z][a-z_\d]*\s*::)*)?/,
              lookbehind: !0,
              alias: 'namespace',
              inside: {
                punctuation: /::/
              }
            }
          ],
          keyword: [
            /\b(?:abstract|as|async|await|become|box|break|const|continue|crate|do|dyn|else|enum|extern|final|fn|for|if|impl|in|let|loop|macro|match|mod|move|mut|override|priv|pub|ref|return|self|Self|static|struct|super|trait|try|type|typeof|union|unsafe|unsized|use|virtual|where|while|yield)\b/,
            /\b(?:[ui](?:8|16|32|64|128|size)|f(?:32|64)|bool|char|str)\b/
          ],
          function : /\b[a-z_]\w*(?=\s*(?:::\s*<|\())/,
          macro: {
            pattern: /\b\w+!/,
            alias: 'property'
          },
          constant: /\b[A-Z_][A-Z_\d]+\b/,
          'class-name': /\b[A-Z]\w*\b/,
          namespace: {
            pattern: /(?:\b[a-z][a-z_\d]*\s*::\s*)*\b[a-z][a-z_\d]*\s*::(?!\s*<)/,
            inside: {
              punctuation: /::/
            }
          },
          number: /\b(?:0x[\dA-Fa-f](?:_?[\dA-Fa-f])*|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*|(?:(?:\d(?:_?\d)*)?\.)?\d(?:_?\d)*(?:[Ee][+-]?\d+)?)(?:_?(?:[iu](?:8|16|32|64|size)?|f32|f64))?\b/,
          boolean: /\b(?:false|true)\b/,
          punctuation: /->|\.\.=|\.{1,3}|::|[{}[\];(),:]/,
          operator: /[-+*\/%!^]=?|=[=>]?|&[&=]?|\|[|=]?|<<?=?|>>?=?|[@?]/
        },
        e.languages.rust['closure-params'].inside.rest = e.languages.rust,
        e.languages.rust.attribute.inside.string = e.languages.rust.string
      }(d),
      function (e) {
        e.languages.sass = e.languages.extend('css', {
          comment: {
            pattern: /^([ \t]*)\/[\/*].*(?:(?:\r?\n|\r)\1[ \t].+)*/m,
            lookbehind: !0,
            greedy: !0
          }
        }),
        e.languages.insertBefore('sass', 'atrule', {
          'atrule-line': {
            pattern: /^(?:[ \t]*)[@+=].+/m,
            greedy: !0,
            inside: {
              atrule: /(?:@[\w-]+|[+=])/m
            }
          }
        }),
        delete e.languages.sass.atrule;
        var t = /\$[-\w]+|#\{\$[-\w]+\}/,
        n = [
          /[+*\/%]|[=!]=|<=?|>=?|\b(?:and|or|not)\b/,
          {
            pattern: /(\s)-(?=\s)/,
            lookbehind: !0
          }
        ];
        e.languages.insertBefore('sass', 'property', {
          'variable-line': {
            pattern: /^[ \t]*\$.+/m,
            greedy: !0,
            inside: {
              punctuation: /:/,
              variable: t,
              operator: n
            }
          },
          'property-line': {
            pattern: /^[ \t]*(?:[^:\s]+ *:.*|:[^:\s].*)/m,
            greedy: !0,
            inside: {
              property: [
                /[^:\s]+(?=\s*:)/,
                {
                  pattern: /(:)[^:\s]+/,
                  lookbehind: !0
                }
              ],
              punctuation: /:/,
              variable: t,
              operator: n,
              important: e.languages.sass.important
            }
          }
        }),
        delete e.languages.sass.property,
        delete e.languages.sass.important,
        e.languages.insertBefore('sass', 'punctuation', {
          selector: {
            pattern: /^([ \t]*)\S(?:,[^,\r\n]+|[^,\r\n]*)(?:,[^,\r\n]+)*(?:,(?:\r?\n|\r)\1[ \t]+\S(?:,[^,\r\n]+|[^,\r\n]*)(?:,[^,\r\n]+)*)*/m,
            lookbehind: !0,
            greedy: !0
          }
        })
      }(d),
      d.languages.scss = d.languages.extend('css', {
        comment: {
          pattern: /(^|[^\\])(?:\/\*[\s\S]*?\*\/|\/\/.*)/,
          lookbehind: !0
        },
        atrule: {
          pattern: /@[\w-](?:\([^()]+\)|[^()\s]|\s+(?!\s))*?(?=\s+[{;])/,
          inside: {
            rule: /@[\w-]+/
          }
        },
        url: /(?:[-a-z]+-)?url(?=\()/i,
        selector: {
          pattern: /(?=\S)[^@;{}()]?(?:[^@;{}()\s]|\s+(?!\s)|#\{\$[-\w]+\})+(?=\s*\{(?:\}|\s|[^}][^:{}]*[:{][^}]))/m,
          inside: {
            parent: {
              pattern: /&/,
              alias: 'important'
            },
            placeholder: /%[-\w]+/,
            variable: /\$[-\w]+|#\{\$[-\w]+\}/
          }
        },
        property: {
          pattern: /(?:[-\w]|\$[-\w]|#\{\$[-\w]+\})+(?=\s*:)/,
          inside: {
            variable: /\$[-\w]+|#\{\$[-\w]+\}/
          }
        }
      }),
      d.languages.insertBefore('scss', 'atrule', {
        keyword: [
          /@(?:if|else(?: if)?|forward|for|each|while|import|use|extend|debug|warn|mixin|include|function|return|content)\b/i,
          {
            pattern: /( )(?:from|through)(?= )/,
            lookbehind: !0
          }
        ]
      }),
      d.languages.insertBefore('scss', 'important', {
        variable: /\$[-\w]+|#\{\$[-\w]+\}/
      }),
      d.languages.insertBefore('scss', 'function', {
        'module-modifier': {
          pattern: /\b(?:as|with|show|hide)\b/i,
          alias: 'keyword'
        },
        placeholder: {
          pattern: /%[-\w]+/,
          alias: 'selector'
        },
        statement: {
          pattern: /\B!(?:default|optional)\b/i,
          alias: 'keyword'
        },
        boolean: /\b(?:true|false)\b/,
        null: {
          pattern: /\bnull\b/,
          alias: 'keyword'
        },
        operator: {
          pattern: /(\s)(?:[-+*\/%]|[=!]=|<=?|>=?|and|or|not)(?=\s)/,
          lookbehind: !0
        }
      }),
      d.languages.scss.atrule.inside.rest = d.languages.scss,
      d.languages.scala = d.languages.extend('java', {
        'triple-quoted-string': {
          pattern: /"""[\s\S]*?"""/,
          greedy: !0,
          alias: 'string'
        },
        string: {
          pattern: /("|')(?:\\.|(?!\1)[^\\\r\n])*\1/,
          greedy: !0
        },
        keyword: /<-|=>|\b(?:abstract|case|catch|class|def|do|else|extends|final|finally|for|forSome|if|implicit|import|lazy|match|new|null|object|override|package|private|protected|return|sealed|self|super|this|throw|trait|try|type|val|var|while|with|yield)\b/,
        number: /\b0x(?:[\da-f]*\.)?[\da-f]+|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e\d+)?[dfl]?/i,
        builtin: /\b(?:String|Int|Long|Short|Byte|Boolean|Double|Float|Char|Any|AnyRef|AnyVal|Unit|Nothing)\b/,
        symbol: /'[^\d\s\\]\w*/
      }),
      delete d.languages.scala['class-name'],
      delete d.languages.scala.function,
      d.languages.scheme = {
        comment: /;.*|#;\s*(?:\((?:[^()]|\([^()]*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\])|#\|(?:[^#|]|#(?!\|)|\|(?!#)|#\|(?:[^#|]|#(?!\|)|\|(?!#))*\|#)*\|#/,
        string: {
          pattern: /"(?:[^"\\]|\\.)*"/,
          greedy: !0
        },
        symbol: {
          pattern: /'[^()\[\]#'\s]+/,
          greedy: !0
        },
        character: {
          pattern: /#\\(?:[ux][a-fA-F\d]+\b|[-a-zA-Z]+\b|[\uD800-\uDBFF][\uDC00-\uDFFF]|\S)/,
          greedy: !0,
          alias: 'string'
        },
        'lambda-parameter': [
          {
            pattern: /((?:^|[^'`#])[(\[]lambda\s+)(?:[^|()\[\]'\s]+|\|(?:[^\\|]|\\.)*\|)/,
            lookbehind: !0
          },
          {
            pattern: /((?:^|[^'`#])[(\[]lambda\s+[(\[])[^()\[\]']+/,
            lookbehind: !0
          }
        ],
        keyword: {
          pattern: /((?:^|[^'`#])[(\[])(?:begin|case(?:-lambda)?|cond(?:-expand)?|define(?:-library|-macro|-record-type|-syntax|-values)?|defmacro|delay(?:-force)?|do|else|export|except|guard|if|import|include(?:-ci|-library-declarations)?|lambda|let(?:rec)?(?:-syntax|-values|\*)?|let\*-values|only|parameterize|prefix|(?:quasi-?)?quote|rename|set!|syntax-(?:case|rules)|unless|unquote(?:-splicing)?|when)(?=[()\[\]\s]|$)/,
          lookbehind: !0
        },
        builtin: {
          pattern: /((?:^|[^'`#])[(\[])(?:abs|and|append|apply|assoc|ass[qv]|binary-port\?|boolean=?\?|bytevector(?:-append|-copy|-copy!|-length|-u8-ref|-u8-set!|\?)?|caar|cadr|call-with-(?:current-continuation|port|values)|call\/cc|car|cdar|cddr|cdr|ceiling|char(?:->integer|-ready\?|\?|<\?|<=\?|=\?|>\?|>=\?)|close-(?:input-port|output-port|port)|complex\?|cons|current-(?:error|input|output)-port|denominator|dynamic-wind|eof-object\??|eq\?|equal\?|eqv\?|error|error-object(?:-irritants|-message|\?)|eval|even\?|exact(?:-integer-sqrt|-integer\?|\?)?|expt|features|file-error\?|floor(?:-quotient|-remainder|\/)?|flush-output-port|for-each|gcd|get-output-(?:bytevector|string)|inexact\??|input-port(?:-open\?|\?)|integer(?:->char|\?)|lcm|length|list(?:->string|->vector|-copy|-ref|-set!|-tail|\?)?|make-(?:bytevector|list|parameter|string|vector)|map|max|member|memq|memv|min|modulo|negative\?|newline|not|null\?|number(?:->string|\?)|numerator|odd\?|open-(?:input|output)-(?:bytevector|string)|or|output-port(?:-open\?|\?)|pair\?|peek-char|peek-u8|port\?|positive\?|procedure\?|quotient|raise|raise-continuable|rational\?|rationalize|read-(?:bytevector|bytevector!|char|error\?|line|string|u8)|real\?|remainder|reverse|round|set-c[ad]r!|square|string(?:->list|->number|->symbol|->utf8|->vector|-append|-copy|-copy!|-fill!|-for-each|-length|-map|-ref|-set!|\?|<\?|<=\?|=\?|>\?|>=\?)?|substring|symbol(?:->string|\?|=\?)|syntax-error|textual-port\?|truncate(?:-quotient|-remainder|\/)?|u8-ready\?|utf8->string|values|vector(?:->list|->string|-append|-copy|-copy!|-fill!|-for-each|-length|-map|-ref|-set!|\?)?|with-exception-handler|write-(?:bytevector|char|string|u8)|zero\?)(?=[()\[\]\s]|$)/,
          lookbehind: !0
        },
        operator: {
          pattern: /((?:^|[^'`#])[(\[])(?:[-+*%/]|[<>]=?|=>?)(?=[()\[\]\s]|$)/,
          lookbehind: !0
        },
        number: {
          pattern: RegExp(function (e) {
            for (var t in e) e[t] = e[t].replace(/<[\w\s]+>/g, (function (t) {
              return '(?:' + e[t].trim() + ')'
            }));
            return e[t]
          }({
            '<ureal dec>': '\\d+(?:/\\d+)|(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:e[+-]?\\d+)?',
            '<real dec>': '[+-]?<ureal dec>|[+-](?:inf|nan)\\.0',
            '<imaginary dec>': '[+-](?:<ureal dec>|(?:inf|nan)\\.0)?i',
            '<complex dec>': '<real dec>(?:@<real dec>|<imaginary dec>)?|<imaginary dec>',
            '<num dec>': '(?:#d(?:#[ei])?|#[ei](?:#d)?)?<complex dec>',
            '<ureal box>': '[0-9a-f]+(?:/[0-9a-f]+)?',
            '<real box>': '[+-]?<ureal box>|[+-](?:inf|nan)\\.0',
            '<imaginary box>': '[+-](?:<ureal box>|(?:inf|nan)\\.0)?i',
            '<complex box>': '<real box>(?:@<real box>|<imaginary box>)?|<imaginary box>',
            '<num box>': '#[box](?:#[ei])?|(?:#[ei])?#[box]<complex box>',
            '<number>': '(^|[()\\[\\]\\s])(?:<num dec>|<num box>)(?=[()\\[\\]\\s]|$)'
          }), 'i'),
          lookbehind: !0
        },
        boolean: {
          pattern: /(^|[()\[\]\s])#(?:[ft]|false|true)(?=[()\[\]\s]|$)/,
          lookbehind: !0
        },
        function : {
          pattern: /((?:^|[^'`#])[(\[])(?:[^|()\[\]'\s]+|\|(?:[^\\|]|\\.)*\|)(?=[()\[\]\s]|$)/,
          lookbehind: !0
        },
        identifier: {
          pattern: /(^|[()\[\]\s])\|(?:[^\\|]|\\.)*\|(?=[()\[\]\s]|$)/,
          lookbehind: !0,
          greedy: !0
        },
        punctuation: /[()\[\]']/
      },
      d.languages.sql = {
        comment: {
          pattern: /(^|[^\\])(?:\/\*[\s\S]*?\*\/|(?:--|\/\/|#).*)/,
          lookbehind: !0
        },
        variable: [
          {
            pattern: /@(["'`])(?:\\[\s\S]|(?!\1)[^\\])+\1/,
            greedy: !0
          },
          /@[\w.$]+/
        ],
        string: {
          pattern: /(^|[^@\\])("|')(?:\\[\s\S]|(?!\2)[^\\]|\2\2)*\2/,
          greedy: !0,
          lookbehind: !0
        },
        function : /\b(?:AVG|COUNT|FIRST|FORMAT|LAST|LCASE|LEN|MAX|MID|MIN|MOD|NOW|ROUND|SUM|UCASE)(?=\s*\()/i,
        keyword: /\b(?:ACTION|ADD|AFTER|ALGORITHM|ALL|ALTER|ANALYZE|ANY|APPLY|AS|ASC|AUTHORIZATION|AUTO_INCREMENT|BACKUP|BDB|BEGIN|BERKELEYDB|BIGINT|BINARY|BIT|BLOB|BOOL|BOOLEAN|BREAK|BROWSE|BTREE|BULK|BY|CALL|CASCADED?|CASE|CHAIN|CHAR(?:ACTER|SET)?|CHECK(?:POINT)?|CLOSE|CLUSTERED|COALESCE|COLLATE|COLUMNS?|COMMENT|COMMIT(?:TED)?|COMPUTE|CONNECT|CONSISTENT|CONSTRAINT|CONTAINS(?:TABLE)?|CONTINUE|CONVERT|CREATE|CROSS|CURRENT(?:_DATE|_TIME|_TIMESTAMP|_USER)?|CURSOR|CYCLE|DATA(?:BASES?)?|DATE(?:TIME)?|DAY|DBCC|DEALLOCATE|DEC|DECIMAL|DECLARE|DEFAULT|DEFINER|DELAYED|DELETE|DELIMITERS?|DENY|DESC|DESCRIBE|DETERMINISTIC|DISABLE|DISCARD|DISK|DISTINCT|DISTINCTROW|DISTRIBUTED|DO|DOUBLE|DROP|DUMMY|DUMP(?:FILE)?|DUPLICATE|ELSE(?:IF)?|ENABLE|ENCLOSED|END|ENGINE|ENUM|ERRLVL|ERRORS|ESCAPED?|EXCEPT|EXEC(?:UTE)?|EXISTS|EXIT|EXPLAIN|EXTENDED|FETCH|FIELDS|FILE|FILLFACTOR|FIRST|FIXED|FLOAT|FOLLOWING|FOR(?: EACH ROW)?|FORCE|FOREIGN|FREETEXT(?:TABLE)?|FROM|FULL|FUNCTION|GEOMETRY(?:COLLECTION)?|GLOBAL|GOTO|GRANT|GROUP|HANDLER|HASH|HAVING|HOLDLOCK|HOUR|IDENTITY(?:_INSERT|COL)?|IF|IGNORE|IMPORT|INDEX|INFILE|INNER|INNODB|INOUT|INSERT|INT|INTEGER|INTERSECT|INTERVAL|INTO|INVOKER|ISOLATION|ITERATE|JOIN|KEYS?|KILL|LANGUAGE|LAST|LEAVE|LEFT|LEVEL|LIMIT|LINENO|LINES|LINESTRING|LOAD|LOCAL|LOCK|LONG(?:BLOB|TEXT)|LOOP|MATCH(?:ED)?|MEDIUM(?:BLOB|INT|TEXT)|MERGE|MIDDLEINT|MINUTE|MODE|MODIFIES|MODIFY|MONTH|MULTI(?:LINESTRING|POINT|POLYGON)|NATIONAL|NATURAL|NCHAR|NEXT|NO|NONCLUSTERED|NULLIF|NUMERIC|OFF?|OFFSETS?|ON|OPEN(?:DATASOURCE|QUERY|ROWSET)?|OPTIMIZE|OPTION(?:ALLY)?|ORDER|OUT(?:ER|FILE)?|OVER|PARTIAL|PARTITION|PERCENT|PIVOT|PLAN|POINT|POLYGON|PRECEDING|PRECISION|PREPARE|PREV|PRIMARY|PRINT|PRIVILEGES|PROC(?:EDURE)?|PUBLIC|PURGE|QUICK|RAISERROR|READS?|REAL|RECONFIGURE|REFERENCES|RELEASE|RENAME|REPEAT(?:ABLE)?|REPLACE|REPLICATION|REQUIRE|RESIGNAL|RESTORE|RESTRICT|RETURN(?:S|ING)?|REVOKE|RIGHT|ROLLBACK|ROUTINE|ROW(?:COUNT|GUIDCOL|S)?|RTREE|RULE|SAVE(?:POINT)?|SCHEMA|SECOND|SELECT|SERIAL(?:IZABLE)?|SESSION(?:_USER)?|SET(?:USER)?|SHARE|SHOW|SHUTDOWN|SIMPLE|SMALLINT|SNAPSHOT|SOME|SONAME|SQL|START(?:ING)?|STATISTICS|STATUS|STRIPED|SYSTEM_USER|TABLES?|TABLESPACE|TEMP(?:ORARY|TABLE)?|TERMINATED|TEXT(?:SIZE)?|THEN|TIME(?:STAMP)?|TINY(?:BLOB|INT|TEXT)|TOP?|TRAN(?:SACTIONS?)?|TRIGGER|TRUNCATE|TSEQUAL|TYPES?|UNBOUNDED|UNCOMMITTED|UNDEFINED|UNION|UNIQUE|UNLOCK|UNPIVOT|UNSIGNED|UPDATE(?:TEXT)?|USAGE|USE|USER|USING|VALUES?|VAR(?:BINARY|CHAR|CHARACTER|YING)|VIEW|WAITFOR|WARNINGS|WHEN|WHERE|WHILE|WITH(?: ROLLUP|IN)?|WORK|WRITE(?:TEXT)?|YEAR)\b/i,
        boolean: /\b(?:TRUE|FALSE|NULL)\b/i,
        number: /\b0x[\da-f]+\b|\b\d+(?:\.\d*)?|\B\.\d+\b/i,
        operator: /[-+*\/=%^~]|&&?|\|\|?|!=?|<(?:=>?|<|>)?|>[>=]?|\b(?:AND|BETWEEN|DIV|IN|ILIKE|IS|LIKE|NOT|OR|REGEXP|RLIKE|SOUNDS LIKE|XOR)\b/i,
        punctuation: /[;[\]()`,.]/
      },
      function (e) {
        var t = {
          pattern: /(\b\d+)(?:%|[a-z]+)/,
          lookbehind: !0
        },
        n = {
          pattern: /(^|[^\w.-])-?(?:\d+(?:\.\d+)?|\.\d+)/,
          lookbehind: !0
        },
        a = {
          comment: {
            pattern: /(^|[^\\])(?:\/\*[\s\S]*?\*\/|\/\/.*)/,
            lookbehind: !0
          },
          url: {
            pattern: /\burl\((["']?).*?\1\)/i,
            greedy: !0
          },
          string: {
            pattern: /("|')(?:(?!\1)[^\\\r\n]|\\(?:\r\n|[\s\S]))*\1/,
            greedy: !0
          },
          interpolation: null,
          func: null,
          important: /\B!(?:important|optional)\b/i,
          keyword: {
            pattern: /(^|\s+)(?:(?:if|else|for|return|unless)(?=\s|$)|@[\w-]+)/,
            lookbehind: !0
          },
          hexcode: /#[\da-f]{3,6}/i,
          color: [
            /\b(?:AliceBlue|AntiqueWhite|Aqua|Aquamarine|Azure|Beige|Bisque|Black|BlanchedAlmond|Blue|BlueViolet|Brown|BurlyWood|CadetBlue|Chartreuse|Chocolate|Coral|CornflowerBlue|Cornsilk|Crimson|Cyan|DarkBlue|DarkCyan|DarkGoldenRod|DarkGr[ae]y|DarkGreen|DarkKhaki|DarkMagenta|DarkOliveGreen|DarkOrange|DarkOrchid|DarkRed|DarkSalmon|DarkSeaGreen|DarkSlateBlue|DarkSlateGr[ae]y|DarkTurquoise|DarkViolet|DeepPink|DeepSkyBlue|DimGr[ae]y|DodgerBlue|FireBrick|FloralWhite|ForestGreen|Fuchsia|Gainsboro|GhostWhite|Gold|GoldenRod|Gr[ae]y|Green|GreenYellow|HoneyDew|HotPink|IndianRed|Indigo|Ivory|Khaki|Lavender|LavenderBlush|LawnGreen|LemonChiffon|LightBlue|LightCoral|LightCyan|LightGoldenRodYellow|LightGr[ae]y|LightGreen|LightPink|LightSalmon|LightSeaGreen|LightSkyBlue|LightSlateGr[ae]y|LightSteelBlue|LightYellow|Lime|LimeGreen|Linen|Magenta|Maroon|MediumAquaMarine|MediumBlue|MediumOrchid|MediumPurple|MediumSeaGreen|MediumSlateBlue|MediumSpringGreen|MediumTurquoise|MediumVioletRed|MidnightBlue|MintCream|MistyRose|Moccasin|NavajoWhite|Navy|OldLace|Olive|OliveDrab|Orange|OrangeRed|Orchid|PaleGoldenRod|PaleGreen|PaleTurquoise|PaleVioletRed|PapayaWhip|PeachPuff|Peru|Pink|Plum|PowderBlue|Purple|Red|RosyBrown|RoyalBlue|SaddleBrown|Salmon|SandyBrown|SeaGreen|SeaShell|Sienna|Silver|SkyBlue|SlateBlue|SlateGr[ae]y|Snow|SpringGreen|SteelBlue|Tan|Teal|Thistle|Tomato|Transparent|Turquoise|Violet|Wheat|White|WhiteSmoke|Yellow|YellowGreen)\b/i,
            {
              pattern: /\b(?:rgb|hsl)\(\s*\d{1,3}\s*,\s*\d{1,3}%?\s*,\s*\d{1,3}%?\s*\)\B|\b(?:rgb|hsl)a\(\s*\d{1,3}\s*,\s*\d{1,3}%?\s*,\s*\d{1,3}%?\s*,\s*(?:0|0?\.\d+|1)\s*\)\B/i,
              inside: {
                unit: t,
                number: n,
                function : /[\w-]+(?=\()/,
                punctuation: /[(),]/
              }
            }
          ],
          entity: /\\[\da-f]{1,8}/i,
          unit: t,
          boolean: /\b(?:true|false)\b/,
          operator: [
            /~|[+!\/%<>?=]=?|[-:]=|\*[*=]?|\.{2,3}|&&|\|\||\B-\B|\b(?:and|in|is(?: a| defined| not|nt)?|not|or)\b/
          ],
          number: n,
          punctuation: /[{}()\[\];:,]/
        };
        a.interpolation = {
          pattern: /\{[^\r\n}:]+\}/,
          alias: 'variable',
          inside: {
            delimiter: {
              pattern: /^\{|\}$/,
              alias: 'punctuation'
            },
            rest: a
          }
        },
        a.func = {
          pattern: /[\w-]+\([^)]*\).*/,
          inside: {
            function : /^[^(]+/,
            rest: a
          }
        },
        e.languages.stylus = {
          'atrule-declaration': {
            pattern: /(^[ \t]*)@.+/m,
            lookbehind: !0,
            inside: {
              atrule: /^@[\w-]+/,
              rest: a
            }
          },
          'variable-declaration': {
            pattern: /(^[ \t]*)[\w$-]+\s*.?=[ \t]*(?:\{[^{}]*\}|\S.*|$)/m,
            lookbehind: !0,
            inside: {
              variable: /^\S+/,
              rest: a
            }
          },
          statement: {
            pattern: /(^[ \t]*)(?:if|else|for|return|unless)[ \t].+/m,
            lookbehind: !0,
            inside: {
              keyword: /^\S+/,
              rest: a
            }
          },
          'property-declaration': {
            pattern: /((?:^|\{)([ \t]*))(?:[\w-]|\{[^}\r\n]+\})+(?:\s*:\s*|[ \t]+)(?!\s)[^{\r\n]*(?:;|[^{\r\n,]$(?!(?:\r?\n|\r)(?:\{|\2[ \t])))/m,
            lookbehind: !0,
            inside: {
              property: {
                pattern: /^[^\s:]+/,
                inside: {
                  interpolation: a.interpolation
                }
              },
              rest: a
            }
          },
          selector: {
            pattern: /(^[ \t]*)(?:(?=\S)(?:[^{}\r\n:()]|::?[\w-]+(?:\([^)\r\n]*\)|(?![\w-]))|\{[^}\r\n]+\})+)(?:(?:\r?\n|\r)(?:\1(?:(?=\S)(?:[^{}\r\n:()]|::?[\w-]+(?:\([^)\r\n]*\)|(?![\w-]))|\{[^}\r\n]+\})+)))*(?:,$|\{|(?=(?:\r?\n|\r)(?:\{|\1[ \t])))/m,
            lookbehind: !0,
            inside: {
              interpolation: a.interpolation,
              comment: a.comment,
              punctuation: /[{},]/
            }
          },
          func: a.func,
          string: a.string,
          comment: {
            pattern: /(^|[^\\])(?:\/\*[\s\S]*?\*\/|\/\/.*)/,
            lookbehind: !0,
            greedy: !0
          },
          interpolation: a.interpolation,
          punctuation: /[{}()\[\];:.]/
        }
      }(d),
      d.languages.swift = {
        comment: {
          pattern: /(^|[^\\:])(?:\/\/.*|\/\*(?:[^/*]|\/(?!\*)|\*(?!\/)|\/\*(?:[^*]|\*(?!\/))*\*\/)*\*\/)/,
          lookbehind: !0,
          greedy: !0
        },
        'string-literal': [
          {
            pattern: RegExp('(^|[^"#])(?:"(?:\\\\(?:\\((?:[^()]|\\([^()]*\\))*\\)|\r\n|[^(])|[^\\\\\r\n"])*"|"""(?:\\\\(?:\\((?:[^()]|\\([^()]*\\))*\\)|[^(])|[^\\\\"]|"(?!""))*""")(?!["#])'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              interpolation: {
                pattern: /(\\\()(?:[^()]|\([^()]*\))*(?=\))/,
                lookbehind: !0,
                inside: null
              },
              'interpolation-punctuation': {
                pattern: /^\)|\\\($/,
                alias: 'punctuation'
              },
              punctuation: /\\(?=[\r\n])/,
              string: /[\s\S]+/
            }
          },
          {
            pattern: RegExp('(^|[^"#])(#+)(?:"(?:\\\\(?:#+\\((?:[^()]|\\([^()]*\\))*\\)|\r\n|[^#])|[^\\\\\r\n])*?"|"""(?:\\\\(?:#+\\((?:[^()]|\\([^()]*\\))*\\)|[^#])|[^\\\\])*?""")\\2'),
            lookbehind: !0,
            greedy: !0,
            inside: {
              interpolation: {
                pattern: /(\\#+\()(?:[^()]|\([^()]*\))*(?=\))/,
                lookbehind: !0,
                inside: null
              },
              'interpolation-punctuation': {
                pattern: /^\)|\\#+\($/,
                alias: 'punctuation'
              },
              string: /[\s\S]+/
            }
          }
        ],
        directive: {
          pattern: RegExp('#(?:(?:elseif|if)\\b(?:[ \t]*(?:![ \t]*)?(?:\\b\\w+\\b(?:[ \t]*\\((?:[^()]|\\([^()]*\\))*\\))?|\\((?:[^()]|\\([^()]*\\))*\\))(?:[ \t]*(?:&&|\\|\\|))?)+|(?:else|endif)\\b)'),
          alias: 'property',
          inside: {
            'directive-name': /^#\w+/,
            boolean: /\b(?:true|false)\b/,
            number: /\b\d+(?:\.\d+)*\b/,
            operator: /!|&&|\|\||[<>]=?/,
            punctuation: /[(),]/
          }
        },
        literal: {
          pattern: /#(?:colorLiteral|column|dsohandle|file(?:ID|Literal|Path)?|function|imageLiteral|line)\b/,
          alias: 'constant'
        },
        'other-directive': {
          pattern: /#\w+\b/,
          alias: 'property'
        },
        attribute: {
          pattern: /@\w+/,
          alias: 'atrule'
        },
        'function-definition': {
          pattern: /(\bfunc\s+)\w+/,
          lookbehind: !0,
          alias: 'function'
        },
        label: {
          pattern: /\b(break|continue)\s+\w+|\b[a-zA-Z_]\w*(?=\s*:\s*(?:for|repeat|while)\b)/,
          lookbehind: !0,
          alias: 'important'
        },
        keyword: /\b(?:Any|Protocol|Self|Type|actor|as|assignment|associatedtype|associativity|async|await|break|case|catch|class|continue|convenience|default|defer|deinit|didSet|do|dynamic|else|enum|extension|fallthrough|fileprivate|final|for|func|get|guard|higherThan|if|import|in|indirect|infix|init|inout|internal|is|lazy|left|let|lowerThan|mutating|none|nonisolated|nonmutating|open|operator|optional|override|postfix|precedencegroup|prefix|private|protocol|public|repeat|required|rethrows|return|right|safe|self|set|some|static|struct|subscript|super|switch|throw|throws|try|typealias|unowned|unsafe|var|weak|where|while|willSet)\b/,
        boolean: /\b(?:true|false)\b/,
        nil: {
          pattern: /\bnil\b/,
          alias: 'constant'
        },
        'short-argument': /\$\d+\b/,
        omit: {
          pattern: /\b_\b/,
          alias: 'keyword'
        },
        number: /\b(?:[\d_]+(?:\.[\de_]+)?|0x[a-f0-9_]+(?:\.[a-f0-9p_]+)?|0b[01_]+|0o[0-7_]+)\b/i,
        'class-name': /\b[A-Z](?:[A-Z_\d]*[a-z]\w*)?\b/,
        function : /\b[a-z_]\w*(?=\s*\()/i,
        constant: /\b(?:[A-Z_]{2,}|k[A-Z][A-Za-z_]+)\b/,
        operator: /[-+*/%=!<>&|^~?]+|\.[.\-+*/%=!<>&|^~?]+/,
        punctuation: /[{}[\]();,.:\\]/
      },
      d.languages.swift['string-literal'].forEach((function (e) {
        e.inside.interpolation.inside = d.languages.swift
      })),
      function (e) {
        function t(e, t) {
          return RegExp(e.replace(/<MOD>/g, (function () {
            return '(?:\\([^|()\n]+\\)|\\[[^\\]\n]+\\]|\\{[^}\n]+\\})'
          })).replace(/<PAR>/g, (function () {
            return '(?:\\)|\\((?![^|()\n]+\\)))'
          })), t || '')
        }
        var n = {
          css: {
            pattern: /\{[^{}]+\}/,
            inside: {
              rest: e.languages.css
            }
          },
          'class-id': {
            pattern: /(\()[^()]+(?=\))/,
            lookbehind: !0,
            alias: 'attr-value'
          },
          lang: {
            pattern: /(\[)[^\[\]]+(?=\])/,
            lookbehind: !0,
            alias: 'attr-value'
          },
          punctuation: /[\\\/]\d+|\S/
        },
        a = e.languages.textile = e.languages.extend('markup', {
          phrase: {
            pattern: /(^|\r|\n)\S[\s\S]*?(?=$|\r?\n\r?\n|\r\r)/,
            lookbehind: !0,
            inside: {
              'block-tag': {
                pattern: t('^[a-z]\\w*(?:<MOD>|<PAR>|[<>=])*\\.'),
                inside: {
                  modifier: {
                    pattern: t('(^[a-z]\\w*)(?:<MOD>|<PAR>|[<>=])+(?=\\.)'),
                    lookbehind: !0,
                    inside: n
                  },
                  tag: /^[a-z]\w*/,
                  punctuation: /\.$/
                }
              },
              list: {
                pattern: t('^[*#]+<MOD>*\\s+\\S.*', 'm'),
                inside: {
                  modifier: {
                    pattern: t('(^[*#]+)<MOD>+'),
                    lookbehind: !0,
                    inside: n
                  },
                  punctuation: /^[*#]+/
                }
              },
              table: {
                pattern: t('^(?:(?:<MOD>|<PAR>|[<>=^~])+\\.\\s*)?(?:\\|(?:(?:<MOD>|<PAR>|[<>=^~_]|[\\\\/]\\d+)+\\.|(?!(?:<MOD>|<PAR>|[<>=^~_]|[\\\\/]\\d+)+\\.))[^|]*)+\\|', 'm'),
                inside: {
                  modifier: {
                    pattern: t('(^|\\|(?:\r?\n|\r)?)(?:<MOD>|<PAR>|[<>=^~_]|[\\\\/]\\d+)+(?=\\.)'),
                    lookbehind: !0,
                    inside: n
                  },
                  punctuation: /\||^\./
                }
              },
              inline: {
                pattern: t('(^|[^a-zA-Z\\d])(\\*\\*|__|\\?\\?|[*_%@+\\-^~])<MOD>*.+?\\2(?![a-zA-Z\\d])'),
                lookbehind: !0,
                inside: {
                  bold: {
                    pattern: t('(^(\\*\\*?)<MOD>*).+?(?=\\2)'),
                    lookbehind: !0
                  },
                  italic: {
                    pattern: t('(^(__?)<MOD>*).+?(?=\\2)'),
                    lookbehind: !0
                  },
                  cite: {
                    pattern: t('(^\\?\\?<MOD>*).+?(?=\\?\\?)'),
                    lookbehind: !0,
                    alias: 'string'
                  },
                  code: {
                    pattern: t('(^@<MOD>*).+?(?=@)'),
                    lookbehind: !0,
                    alias: 'keyword'
                  },
                  inserted: {
                    pattern: t('(^\\+<MOD>*).+?(?=\\+)'),
                    lookbehind: !0
                  },
                  deleted: {
                    pattern: t('(^-<MOD>*).+?(?=-)'),
                    lookbehind: !0
                  },
                  span: {
                    pattern: t('(^%<MOD>*).+?(?=%)'),
                    lookbehind: !0
                  },
                  modifier: {
                    pattern: t('(^\\*\\*|__|\\?\\?|[*_%@+\\-^~])<MOD>+'),
                    lookbehind: !0,
                    inside: n
                  },
                  punctuation: /[*_%?@+\-^~]+/
                }
              },
              'link-ref': {
                pattern: /^\[[^\]]+\]\S+$/m,
                inside: {
                  string: {
                    pattern: /(^\[)[^\]]+(?=\])/,
                    lookbehind: !0
                  },
                  url: {
                    pattern: /(^\])\S+$/,
                    lookbehind: !0
                  },
                  punctuation: /[\[\]]/
                }
              },
              link: {
                pattern: t('"<MOD>*[^"]+":.+?(?=[^\\w/]?(?:\\s|$))'),
                inside: {
                  text: {
                    pattern: t('(^"<MOD>*)[^"]+(?=")'),
                    lookbehind: !0
                  },
                  modifier: {
                    pattern: t('(^")<MOD>+'),
                    lookbehind: !0,
                    inside: n
                  },
                  url: {
                    pattern: /(:).+/,
                    lookbehind: !0
                  },
                  punctuation: /[":]/
                }
              },
              image: {
                pattern: t('!(?:<MOD>|<PAR>|[<>=])*(?![<>=])[^!\\s()]+(?:\\([^)]+\\))?!(?::.+?(?=[^\\w/]?(?:\\s|$)))?'),
                inside: {
                  source: {
                    pattern: t('(^!(?:<MOD>|<PAR>|[<>=])*)(?![<>=])[^!\\s()]+(?:\\([^)]+\\))?(?=!)'),
                    lookbehind: !0,
                    alias: 'url'
                  },
                  modifier: {
                    pattern: t('(^!)(?:<MOD>|<PAR>|[<>=])+'),
                    lookbehind: !0,
                    inside: n
                  },
                  url: {
                    pattern: /(:).+/,
                    lookbehind: !0
                  },
                  punctuation: /[!:]/
                }
              },
              footnote: {
                pattern: /\b\[\d+\]/,
                alias: 'comment',
                inside: {
                  punctuation: /\[|\]/
                }
              },
              acronym: {
                pattern: /\b[A-Z\d]+\([^)]+\)/,
                inside: {
                  comment: {
                    pattern: /(\()[^()]+(?=\))/,
                    lookbehind: !0
                  },
                  punctuation: /[()]/
                }
              },
              mark: {
                pattern: /\b\((?:TM|R|C)\)/,
                alias: 'comment',
                inside: {
                  punctuation: /[()]/
                }
              }
            }
          }
        }),
        r = a.phrase.inside,
        i = {
          inline: r.inline,
          link: r.link,
          image: r.image,
          footnote: r.footnote,
          acronym: r.acronym,
          mark: r.mark
        };
        a.tag.pattern = /<\/?(?!\d)[a-z0-9]+(?:\s+[^\s>\/=]+(?:=(?:("|')(?:\\[\s\S]|(?!\1)[^\\])*\1|[^\s'">=]+))?)*\s*\/?>/i;
        var o = r.inline.inside;
        o.bold.inside = i,
        o.italic.inside = i,
        o.inserted.inside = i,
        o.deleted.inside = i,
        o.span.inside = i;
        var s = r.table.inside;
        s.inline = i.inline,
        s.link = i.link,
        s.image = i.image,
        s.footnote = i.footnote,
        s.acronym = i.acronym,
        s.mark = i.mark
      }(d),
      function (e) {
        function t(e) {
          return e.replace(/__/g, (function () {
            return '(?:[\\w-]+|\'[^\'\n\r]*\'|"(?:\\\\.|[^\\\\"\r\n])*")'
          }))
        }
        e.languages.toml = {
          comment: {
            pattern: /#.*/,
            greedy: !0
          },
          table: {
            pattern: RegExp(t('(^[\t ]*\\[\\s*(?:\\[\\s*)?)__(?:\\s*\\.\\s*__)*(?=\\s*\\])'), 'm'),
            lookbehind: !0,
            greedy: !0,
            alias: 'class-name'
          },
          key: {
            pattern: RegExp(t('(^[\t ]*|[{,]\\s*)__(?:\\s*\\.\\s*__)*(?=\\s*=)'), 'm'),
            lookbehind: !0,
            greedy: !0,
            alias: 'property'
          },
          string: {
            pattern: /"""(?:\\[\s\S]|[^\\])*?"""|'''[\s\S]*?'''|'[^'\n\r]*'|"(?:\\.|[^\\"\r\n])*"/,
            greedy: !0
          },
          date: [
            {
              pattern: /\b\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b/i,
              alias: 'number'
            },
            {
              pattern: /\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b/,
              alias: 'number'
            }
          ],
          number: /(?:\b0(?:x[\da-zA-Z]+(?:_[\da-zA-Z]+)*|o[0-7]+(?:_[0-7]+)*|b[10]+(?:_[10]+)*))\b|[-+]?\b\d+(?:_\d+)*(?:\.\d+(?:_\d+)*)?(?:[eE][+-]?\d+(?:_\d+)*)?\b|[-+]?\b(?:inf|nan)\b/,
          boolean: /\b(?:true|false)\b/,
          punctuation: /[.,=[\]{}]/
        }
      }(d),
      d.languages.twig = {
        comment: /\{#[\s\S]*?#\}/,
        tag: {
          pattern: /\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}/,
          inside: {
            ld: {
              pattern: /^(?:\{\{-?|\{%-?\s*\w+)/,
              inside: {
                punctuation: /^(?:\{\{|\{%)-?/,
                keyword: /\w+/
              }
            },
            rd: {
              pattern: /-?(?:%\}|\}\})$/,
              inside: {
                punctuation: /.+/
              }
            },
            string: {
              pattern: /("|')(?:\\.|(?!\1)[^\\\r\n])*\1/,
              inside: {
                punctuation: /^['"]|['"]$/
              }
            },
            keyword: /\b(?:even|if|odd)\b/,
            boolean: /\b(?:true|false|null)\b/,
            number: /\b0x[\dA-Fa-f]+|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:[Ee][-+]?\d+)?/,
            operator: [
              {
                pattern: /(\s)(?:and|b-and|b-xor|b-or|ends with|in|is|matches|not|or|same as|starts with)(?=\s)/,
                lookbehind: !0
              },
              /[=<>]=?|!=|\*\*?|\/\/?|\?:?|[-+~%|]/
            ],
            property: /\b[a-zA-Z_]\w*\b/,
            punctuation: /[()\[\]{}:.,]/
          }
        },
        other: {
          pattern: /\S(?:[\s\S]*\S)?/,
          inside: d.languages.markup
        }
      },
      d.languages.vim = {
        string: /"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\r\n]|'')*'/,
        comment: /".*/,
        function : /\b\w+(?=\()/,
        keyword: /\b(?:ab|abbreviate|abc|abclear|abo|aboveleft|al|all|arga|argadd|argd|argdelete|argdo|arge|argedit|argg|argglobal|argl|arglocal|ar|args|argu|argument|as|ascii|bad|badd|ba|ball|bd|bdelete|be|bel|belowright|bf|bfirst|bl|blast|bm|bmodified|bn|bnext|bN|bNext|bo|botright|bp|bprevious|brea|break|breaka|breakadd|breakd|breakdel|breakl|breaklist|br|brewind|bro|browse|bufdo|b|buffer|buffers|bun|bunload|bw|bwipeout|ca|cabbrev|cabc|cabclear|caddb|caddbuffer|cad|caddexpr|caddf|caddfile|cal|call|cat|catch|cb|cbuffer|cc|ccl|cclose|cd|ce|center|cex|cexpr|cf|cfile|cfir|cfirst|cgetb|cgetbuffer|cgete|cgetexpr|cg|cgetfile|c|change|changes|chd|chdir|che|checkpath|checkt|checktime|cla|clast|cl|clist|clo|close|cmapc|cmapclear|cnew|cnewer|cn|cnext|cN|cNext|cnf|cnfile|cNfcNfile|cnorea|cnoreabbrev|col|colder|colo|colorscheme|comc|comclear|comp|compiler|conf|confirm|con|continue|cope|copen|co|copy|cpf|cpfile|cp|cprevious|cq|cquit|cr|crewind|cuna|cunabbrev|cu|cunmap|cw|cwindow|debugg|debuggreedy|delc|delcommand|d|delete|delf|delfunction|delm|delmarks|diffg|diffget|diffoff|diffpatch|diffpu|diffput|diffsplit|diffthis|diffu|diffupdate|dig|digraphs|di|display|dj|djump|dl|dlist|dr|drop|ds|dsearch|dsp|dsplit|earlier|echoe|echoerr|echom|echomsg|echon|e|edit|el|else|elsei|elseif|em|emenu|endfo|endfor|endf|endfunction|endfun|en|endif|endt|endtry|endw|endwhile|ene|enew|ex|exi|exit|exu|exusage|f|file|files|filetype|fina|finally|fin|find|fini|finish|fir|first|fix|fixdel|fo|fold|foldc|foldclose|folddoc|folddoclosed|foldd|folddoopen|foldo|foldopen|for|fu|fun|function|go|goto|gr|grep|grepa|grepadd|ha|hardcopy|h|help|helpf|helpfind|helpg|helpgrep|helpt|helptags|hid|hide|his|history|ia|iabbrev|iabc|iabclear|if|ij|ijump|il|ilist|imapc|imapclear|in|inorea|inoreabbrev|isearch|isp|isplit|iuna|iunabbrev|iu|iunmap|j|join|ju|jumps|k|keepalt|keepj|keepjumps|kee|keepmarks|laddb|laddbuffer|lad|laddexpr|laddf|laddfile|lan|language|la|last|later|lb|lbuffer|lc|lcd|lch|lchdir|lcl|lclose|let|left|lefta|leftabove|lex|lexpr|lf|lfile|lfir|lfirst|lgetb|lgetbuffer|lgete|lgetexpr|lg|lgetfile|lgr|lgrep|lgrepa|lgrepadd|lh|lhelpgrep|l|list|ll|lla|llast|lli|llist|lmak|lmake|lm|lmap|lmapc|lmapclear|lnew|lnewer|lne|lnext|lN|lNext|lnf|lnfile|lNf|lNfile|ln|lnoremap|lo|loadview|loc|lockmarks|lockv|lockvar|lol|lolder|lop|lopen|lpf|lpfile|lp|lprevious|lr|lrewind|ls|lt|ltag|lu|lunmap|lv|lvimgrep|lvimgrepa|lvimgrepadd|lw|lwindow|mak|make|ma|mark|marks|mat|match|menut|menutranslate|mk|mkexrc|mks|mksession|mksp|mkspell|mkvie|mkview|mkv|mkvimrc|mod|mode|m|move|mzf|mzfile|mz|mzscheme|nbkey|new|n|next|N|Next|nmapc|nmapclear|noh|nohlsearch|norea|noreabbrev|nu|number|nun|nunmap|omapc|omapclear|on|only|o|open|opt|options|ou|ounmap|pc|pclose|ped|pedit|pe|perl|perld|perldo|po|pop|popu|popup|pp|ppop|pre|preserve|prev|previous|p|print|P|Print|profd|profdel|prof|profile|promptf|promptfind|promptr|promptrepl|ps|psearch|pta|ptag|ptf|ptfirst|ptj|ptjump|ptl|ptlast|ptn|ptnext|ptN|ptNext|ptp|ptprevious|ptr|ptrewind|pts|ptselect|pu|put|pw|pwd|pyf|pyfile|py|python|qa|qall|q|quit|quita|quitall|r|read|rec|recover|redi|redir|red|redo|redr|redraw|redraws|redrawstatus|reg|registers|res|resize|ret|retab|retu|return|rew|rewind|ri|right|rightb|rightbelow|rub|ruby|rubyd|rubydo|rubyf|rubyfile|ru|runtime|rv|rviminfo|sal|sall|san|sandbox|sa|sargument|sav|saveas|sba|sball|sbf|sbfirst|sbl|sblast|sbm|sbmodified|sbn|sbnext|sbN|sbNext|sbp|sbprevious|sbr|sbrewind|sb|sbuffer|scripte|scriptencoding|scrip|scriptnames|se|set|setf|setfiletype|setg|setglobal|setl|setlocal|sf|sfind|sfir|sfirst|sh|shell|sign|sil|silent|sim|simalt|sla|slast|sl|sleep|sm|smagic|smap|smapc|smapclear|sme|smenu|sn|snext|sN|sNext|sni|sniff|sno|snomagic|snor|snoremap|snoreme|snoremenu|sor|sort|so|source|spelld|spelldump|spe|spellgood|spelli|spellinfo|spellr|spellrepall|spellu|spellundo|spellw|spellwrong|sp|split|spr|sprevious|sre|srewind|sta|stag|startg|startgreplace|star|startinsert|startr|startreplace|stj|stjump|st|stop|stopi|stopinsert|sts|stselect|sun|sunhide|sunm|sunmap|sus|suspend|sv|sview|syncbind|t|tab|tabc|tabclose|tabd|tabdo|tabe|tabedit|tabf|tabfind|tabfir|tabfirst|tabl|tablast|tabm|tabmove|tabnew|tabn|tabnext|tabN|tabNext|tabo|tabonly|tabp|tabprevious|tabr|tabrewind|tabs|ta|tag|tags|tc|tcl|tcld|tcldo|tclf|tclfile|te|tearoff|tf|tfirst|th|throw|tj|tjump|tl|tlast|tm|tmenu|tn|tnext|tN|tNext|to|topleft|tp|tprevious|tr|trewind|try|ts|tselect|tu|tunmenu|una|unabbreviate|u|undo|undoj|undojoin|undol|undolist|unh|unhide|unlet|unlo|unlockvar|unm|unmap|up|update|verb|verbose|ve|version|vert|vertical|vie|view|vim|vimgrep|vimgrepa|vimgrepadd|vi|visual|viu|viusage|vmapc|vmapclear|vne|vnew|vs|vsplit|vu|vunmap|wa|wall|wh|while|winc|wincmd|windo|winp|winpos|win|winsize|wn|wnext|wN|wNext|wp|wprevious|wq|wqa|wqall|w|write|ws|wsverb|wv|wviminfo|X|xa|xall|x|xit|xm|xmap|xmapc|xmapclear|xme|xmenu|XMLent|XMLns|xn|xnoremap|xnoreme|xnoremenu|xu|xunmap|y|yank)\b/,
        builtin: /\b(?:autocmd|acd|ai|akm|aleph|allowrevins|altkeymap|ambiwidth|ambw|anti|antialias|arab|arabic|arabicshape|ari|arshape|autochdir|autoindent|autoread|autowrite|autowriteall|aw|awa|background|backspace|backup|backupcopy|backupdir|backupext|backupskip|balloondelay|ballooneval|balloonexpr|bdir|bdlay|beval|bex|bexpr|bg|bh|bin|binary|biosk|bioskey|bk|bkc|bomb|breakat|brk|browsedir|bs|bsdir|bsk|bt|bufhidden|buflisted|buftype|casemap|ccv|cdpath|cedit|cfu|ch|charconvert|ci|cin|cindent|cink|cinkeys|cino|cinoptions|cinw|cinwords|clipboard|cmdheight|cmdwinheight|cmp|cms|columns|com|comments|commentstring|compatible|complete|completefunc|completeopt|consk|conskey|copyindent|cot|cpo|cpoptions|cpt|cscopepathcomp|cscopeprg|cscopequickfix|cscopetag|cscopetagorder|cscopeverbose|cspc|csprg|csqf|cst|csto|csverb|cuc|cul|cursorcolumn|cursorline|cwh|debug|deco|def|define|delcombine|dex|dg|dict|dictionary|diff|diffexpr|diffopt|digraph|dip|dir|directory|dy|ea|ead|eadirection|eb|ed|edcompatible|ef|efm|ei|ek|enc|encoding|endofline|eol|ep|equalalways|equalprg|errorbells|errorfile|errorformat|esckeys|et|eventignore|expandtab|exrc|fcl|fcs|fdc|fde|fdi|fdl|fdls|fdm|fdn|fdo|fdt|fen|fenc|fencs|fex|ff|ffs|fileencoding|fileencodings|fileformat|fileformats|fillchars|fk|fkmap|flp|fml|fmr|foldcolumn|foldenable|foldexpr|foldignore|foldlevel|foldlevelstart|foldmarker|foldmethod|foldminlines|foldnestmax|foldtext|formatexpr|formatlistpat|formatoptions|formatprg|fp|fs|fsync|ft|gcr|gd|gdefault|gfm|gfn|gfs|gfw|ghr|gp|grepformat|grepprg|gtl|gtt|guicursor|guifont|guifontset|guifontwide|guiheadroom|guioptions|guipty|guitablabel|guitabtooltip|helpfile|helpheight|helplang|hf|hh|hi|hidden|highlight|hk|hkmap|hkmapp|hkp|hl|hlg|hls|hlsearch|ic|icon|iconstring|ignorecase|im|imactivatekey|imak|imc|imcmdline|imd|imdisable|imi|iminsert|ims|imsearch|inc|include|includeexpr|incsearch|inde|indentexpr|indentkeys|indk|inex|inf|infercase|insertmode|isf|isfname|isi|isident|isk|iskeyword|isprint|joinspaces|js|key|keymap|keymodel|keywordprg|km|kmp|kp|langmap|langmenu|laststatus|lazyredraw|lbr|lcs|linebreak|lines|linespace|lisp|lispwords|listchars|loadplugins|lpl|lsp|lz|macatsui|magic|makeef|makeprg|matchpairs|matchtime|maxcombine|maxfuncdepth|maxmapdepth|maxmem|maxmempattern|maxmemtot|mco|mef|menuitems|mfd|mh|mis|mkspellmem|ml|mls|mm|mmd|mmp|mmt|modeline|modelines|modifiable|modified|more|mouse|mousef|mousefocus|mousehide|mousem|mousemodel|mouses|mouseshape|mouset|mousetime|mp|mps|msm|mzq|mzquantum|nf|nrformats|numberwidth|nuw|odev|oft|ofu|omnifunc|opendevice|operatorfunc|opfunc|osfiletype|pa|para|paragraphs|paste|pastetoggle|patchexpr|patchmode|path|pdev|penc|pex|pexpr|pfn|ph|pheader|pi|pm|pmbcs|pmbfn|popt|preserveindent|previewheight|previewwindow|printdevice|printencoding|printexpr|printfont|printheader|printmbcharset|printmbfont|printoptions|prompt|pt|pumheight|pvh|pvw|qe|quoteescape|readonly|remap|report|restorescreen|revins|rightleft|rightleftcmd|rl|rlc|ro|rs|rtp|ruf|ruler|rulerformat|runtimepath|sbo|sc|scb|scr|scroll|scrollbind|scrolljump|scrolloff|scrollopt|scs|sect|sections|secure|sel|selection|selectmode|sessionoptions|sft|shcf|shellcmdflag|shellpipe|shellquote|shellredir|shellslash|shelltemp|shelltype|shellxquote|shiftround|shiftwidth|shm|shortmess|shortname|showbreak|showcmd|showfulltag|showmatch|showmode|showtabline|shq|si|sidescroll|sidescrolloff|siso|sj|slm|smartcase|smartindent|smarttab|smc|smd|softtabstop|sol|spc|spell|spellcapcheck|spellfile|spelllang|spellsuggest|spf|spl|splitbelow|splitright|sps|sr|srr|ss|ssl|ssop|stal|startofline|statusline|stl|stmp|su|sua|suffixes|suffixesadd|sw|swapfile|swapsync|swb|swf|switchbuf|sws|sxq|syn|synmaxcol|syntax|tabline|tabpagemax|tabstop|tagbsearch|taglength|tagrelative|tagstack|tal|tb|tbi|tbidi|tbis|tbs|tenc|term|termbidi|termencoding|terse|textauto|textmode|textwidth|tgst|thesaurus|tildeop|timeout|timeoutlen|title|titlelen|titleold|titlestring|toolbar|toolbariconsize|top|tpm|tsl|tsr|ttimeout|ttimeoutlen|ttm|tty|ttybuiltin|ttyfast|ttym|ttymouse|ttyscroll|ttytype|tw|tx|uc|ul|undolevels|updatecount|updatetime|ut|vb|vbs|vdir|verbosefile|vfile|viewdir|viewoptions|viminfo|virtualedit|visualbell|vop|wak|warn|wb|wc|wcm|wd|weirdinvert|wfh|wfw|whichwrap|wi|wig|wildchar|wildcharm|wildignore|wildmenu|wildmode|wildoptions|wim|winaltkeys|window|winfixheight|winfixwidth|winheight|winminheight|winminwidth|winwidth|wiv|wiw|wm|wmh|wmnu|wmw|wop|wrap|wrapmargin|wrapscan|writeany|writebackup|writedelay|ww|noacd|noai|noakm|noallowrevins|noaltkeymap|noanti|noantialias|noar|noarab|noarabic|noarabicshape|noari|noarshape|noautochdir|noautoindent|noautoread|noautowrite|noautowriteall|noaw|noawa|nobackup|noballooneval|nobeval|nobin|nobinary|nobiosk|nobioskey|nobk|nobl|nobomb|nobuflisted|nocf|noci|nocin|nocindent|nocompatible|noconfirm|noconsk|noconskey|nocopyindent|nocp|nocscopetag|nocscopeverbose|nocst|nocsverb|nocuc|nocul|nocursorcolumn|nocursorline|nodeco|nodelcombine|nodg|nodiff|nodigraph|nodisable|noea|noeb|noed|noedcompatible|noek|noendofline|noeol|noequalalways|noerrorbells|noesckeys|noet|noex|noexpandtab|noexrc|nofen|nofk|nofkmap|nofoldenable|nogd|nogdefault|noguipty|nohid|nohidden|nohk|nohkmap|nohkmapp|nohkp|nohls|noic|noicon|noignorecase|noim|noimc|noimcmdline|noimd|noincsearch|noinf|noinfercase|noinsertmode|nois|nojoinspaces|nojs|nolazyredraw|nolbr|nolinebreak|nolisp|nolist|noloadplugins|nolpl|nolz|noma|nomacatsui|nomagic|nomh|noml|nomod|nomodeline|nomodifiable|nomodified|nomore|nomousef|nomousefocus|nomousehide|nonu|nonumber|noodev|noopendevice|nopaste|nopi|nopreserveindent|nopreviewwindow|noprompt|nopvw|noreadonly|noremap|norestorescreen|norevins|nori|norightleft|norightleftcmd|norl|norlc|noro|nors|noru|noruler|nosb|nosc|noscb|noscrollbind|noscs|nosecure|nosft|noshellslash|noshelltemp|noshiftround|noshortname|noshowcmd|noshowfulltag|noshowmatch|noshowmode|nosi|nosm|nosmartcase|nosmartindent|nosmarttab|nosmd|nosn|nosol|nospell|nosplitbelow|nosplitright|nospr|nosr|nossl|nosta|nostartofline|nostmp|noswapfile|noswf|nota|notagbsearch|notagrelative|notagstack|notbi|notbidi|notbs|notermbidi|noterse|notextauto|notextmode|notf|notgst|notildeop|notimeout|notitle|noto|notop|notr|nottimeout|nottybuiltin|nottyfast|notx|novb|novisualbell|nowa|nowarn|nowb|noweirdinvert|nowfh|nowfw|nowildmenu|nowinfixheight|nowinfixwidth|nowiv|nowmnu|nowrap|nowrapscan|nowrite|nowriteany|nowritebackup|nows|invacd|invai|invakm|invallowrevins|invaltkeymap|invanti|invantialias|invar|invarab|invarabic|invarabicshape|invari|invarshape|invautochdir|invautoindent|invautoread|invautowrite|invautowriteall|invaw|invawa|invbackup|invballooneval|invbeval|invbin|invbinary|invbiosk|invbioskey|invbk|invbl|invbomb|invbuflisted|invcf|invci|invcin|invcindent|invcompatible|invconfirm|invconsk|invconskey|invcopyindent|invcp|invcscopetag|invcscopeverbose|invcst|invcsverb|invcuc|invcul|invcursorcolumn|invcursorline|invdeco|invdelcombine|invdg|invdiff|invdigraph|invdisable|invea|inveb|inved|invedcompatible|invek|invendofline|inveol|invequalalways|inverrorbells|invesckeys|invet|invex|invexpandtab|invexrc|invfen|invfk|invfkmap|invfoldenable|invgd|invgdefault|invguipty|invhid|invhidden|invhk|invhkmap|invhkmapp|invhkp|invhls|invhlsearch|invic|invicon|invignorecase|invim|invimc|invimcmdline|invimd|invincsearch|invinf|invinfercase|invinsertmode|invis|invjoinspaces|invjs|invlazyredraw|invlbr|invlinebreak|invlisp|invlist|invloadplugins|invlpl|invlz|invma|invmacatsui|invmagic|invmh|invml|invmod|invmodeline|invmodifiable|invmodified|invmore|invmousef|invmousefocus|invmousehide|invnu|invnumber|invodev|invopendevice|invpaste|invpi|invpreserveindent|invpreviewwindow|invprompt|invpvw|invreadonly|invremap|invrestorescreen|invrevins|invri|invrightleft|invrightleftcmd|invrl|invrlc|invro|invrs|invru|invruler|invsb|invsc|invscb|invscrollbind|invscs|invsecure|invsft|invshellslash|invshelltemp|invshiftround|invshortname|invshowcmd|invshowfulltag|invshowmatch|invshowmode|invsi|invsm|invsmartcase|invsmartindent|invsmarttab|invsmd|invsn|invsol|invspell|invsplitbelow|invsplitright|invspr|invsr|invssl|invsta|invstartofline|invstmp|invswapfile|invswf|invta|invtagbsearch|invtagrelative|invtagstack|invtbi|invtbidi|invtbs|invtermbidi|invterse|invtextauto|invtextmode|invtf|invtgst|invtildeop|invtimeout|invtitle|invto|invtop|invtr|invttimeout|invttybuiltin|invttyfast|invtx|invvb|invvisualbell|invwa|invwarn|invwb|invweirdinvert|invwfh|invwfw|invwildmenu|invwinfixheight|invwinfixwidth|invwiv|invwmnu|invwrap|invwrapscan|invwrite|invwriteany|invwritebackup|invws|t_AB|t_AF|t_al|t_AL|t_bc|t_cd|t_ce|t_Ce|t_cl|t_cm|t_Co|t_cs|t_Cs|t_CS|t_CV|t_da|t_db|t_dl|t_DL|t_EI|t_F1|t_F2|t_F3|t_F4|t_F5|t_F6|t_F7|t_F8|t_F9|t_fs|t_IE|t_IS|t_k1|t_K1|t_k2|t_k3|t_K3|t_k4|t_K4|t_k5|t_K5|t_k6|t_K6|t_k7|t_K7|t_k8|t_K8|t_k9|t_K9|t_KA|t_kb|t_kB|t_KB|t_KC|t_kd|t_kD|t_KD|t_ke|t_KE|t_KF|t_KG|t_kh|t_KH|t_kI|t_KI|t_KJ|t_KK|t_kl|t_KL|t_kN|t_kP|t_kr|t_ks|t_ku|t_le|t_mb|t_md|t_me|t_mr|t_ms|t_nd|t_op|t_RI|t_RV|t_Sb|t_se|t_Sf|t_SI|t_so|t_sr|t_te|t_ti|t_ts|t_ue|t_us|t_ut|t_vb|t_ve|t_vi|t_vs|t_WP|t_WS|t_xs|t_ZH|t_ZR)\b/,
        number: /\b(?:0x[\da-f]+|\d+(?:\.\d+)?)\b/i,
        operator: /\|\||&&|[-+.]=?|[=!](?:[=~][#?]?)?|[<>]=?[#?]?|[*\/%?]|\b(?:is(?:not)?)\b/,
        punctuation: /[{}[\](),;:]/
      },
      d.languages['visual-basic'] = {
        comment: {
          pattern: /(?:['‘’]|REM\b)(?:[^\r\n_]|_(?:\r\n?|\n)?)*/i,
          inside: {
            keyword: /^REM/i
          }
        },
        directive: {
          pattern: /#(?:Const|Else|ElseIf|End|ExternalChecksum|ExternalSource|If|Region)(?:[^\S\r\n]_[^\S\r\n]*(?:\r\n?|\n)|.)+/i,
          alias: 'comment',
          greedy: !0
        },
        string: {
          pattern: /\$?["“”](?:["“”]{2}|[^"“”])*["“”]C?/i,
          greedy: !0
        },
        date: {
          pattern: /#[^\S\r\n]*(?:\d+([/-])\d+\1\d+(?:[^\S\r\n]+(?:\d+[^\S\r\n]*(?:AM|PM)|\d+:\d+(?::\d+)?(?:[^\S\r\n]*(?:AM|PM))?))?|\d+[^\S\r\n]*(?:AM|PM)|\d+:\d+(?::\d+)?(?:[^\S\r\n]*(?:AM|PM))?)[^\S\r\n]*#/i,
          alias: 'builtin'
        },
        number: /(?:(?:\b\d+(?:\.\d+)?|\.\d+)(?:E[+-]?\d+)?|&[HO][\dA-F]+)(?:U?[ILS]|[FRD])?/i,
        boolean: /\b(?:True|False|Nothing)\b/i,
        keyword: /\b(?:AddHandler|AddressOf|Alias|And(?:Also)?|As|Boolean|ByRef|Byte|ByVal|Call|Case|Catch|C(?:Bool|Byte|Char|Date|Dbl|Dec|Int|Lng|Obj|SByte|Short|Sng|Str|Type|UInt|ULng|UShort)|Char|Class|Const|Continue|Currency|Date|Decimal|Declare|Default|Delegate|Dim|DirectCast|Do|Double|Each|Else(?:If)?|End(?:If)?|Enum|Erase|Error|Event|Exit|Finally|For|Friend|Function|Get(?:Type|XMLNamespace)?|Global|GoSub|GoTo|Handles|If|Implements|Imports|In|Inherits|Integer|Interface|Is|IsNot|Let|Lib|Like|Long|Loop|Me|Mod|Module|Must(?:Inherit|Override)|My(?:Base|Class)|Namespace|Narrowing|New|Next|Not(?:Inheritable|Overridable)?|Object|Of|On|Operator|Option(?:al)?|Or(?:Else)?|Out|Overloads|Overridable|Overrides|ParamArray|Partial|Private|Property|Protected|Public|RaiseEvent|ReadOnly|ReDim|RemoveHandler|Resume|Return|SByte|Select|Set|Shadows|Shared|short|Single|Static|Step|Stop|String|Structure|Sub|SyncLock|Then|Throw|To|Try|TryCast|Type|TypeOf|U(?:Integer|Long|Short)|Using|Variant|Wend|When|While|Widening|With(?:Events)?|WriteOnly|Until|Xor)\b/i,
        operator: [
          /[+\-*/\\^<=>&#@$%!]/,
          {
            pattern: /([^\S\r\n])_(?=[^\S\r\n]*[\r\n])/,
            lookbehind: !0
          }
        ],
        punctuation: /[{}().,:?]/
      },
      d.languages.vb = d.languages['visual-basic'],
      d.languages.vba = d.languages['visual-basic'],
      d.languages.wasm = {
        comment: [
          /\(;[\s\S]*?;\)/,
          {
            pattern: /;;.*/,
            greedy: !0
          }
        ],
        string: {
          pattern: /"(?:\\[\s\S]|[^"\\])*"/,
          greedy: !0
        },
        keyword: [
          {
            pattern: /\b(?:align|offset)=/,
            inside: {
              operator: /=/
            }
          },
          {
            pattern: /\b(?:(?:f32|f64|i32|i64)(?:\.(?:abs|add|and|ceil|clz|const|convert_[su]\/i(?:32|64)|copysign|ctz|demote\/f64|div(?:_[su])?|eqz?|extend_[su]\/i32|floor|ge(?:_[su])?|gt(?:_[su])?|le(?:_[su])?|load(?:(?:8|16|32)_[su])?|lt(?:_[su])?|max|min|mul|nearest|neg?|or|popcnt|promote\/f32|reinterpret\/[fi](?:32|64)|rem_[su]|rot[lr]|shl|shr_[su]|store(?:8|16|32)?|sqrt|sub|trunc(?:_[su]\/f(?:32|64))?|wrap\/i64|xor))?|memory\.(?:grow|size))\b/,
            inside: {
              punctuation: /\./
            }
          },
          /\b(?:anyfunc|block|br(?:_if|_table)?|call(?:_indirect)?|data|drop|elem|else|end|export|func|get_(?:global|local)|global|if|import|local|loop|memory|module|mut|nop|offset|param|result|return|select|set_(?:global|local)|start|table|tee_local|then|type|unreachable)\b/
        ],
        variable: /\$[\w!#$%&'*+\-./:<=>?@\\^`|~]+/i,
        number: /[+-]?\b(?:\d(?:_?\d)*(?:\.\d(?:_?\d)*)?(?:[eE][+-]?\d(?:_?\d)*)?|0x[\da-fA-F](?:_?[\da-fA-F])*(?:\.[\da-fA-F](?:_?[\da-fA-D])*)?(?:[pP][+-]?\d(?:_?\d)*)?)\b|\binf\b|\bnan(?::0x[\da-fA-F](?:_?[\da-fA-D])*)?\b/,
        punctuation: /[()]/
      },
      function (e) {
        var t = /[*&][^\s[\]{},]+/,
        n = /!(?:<[\w\-%#;/?:@&=+$,.!~*'()[\]]+>|(?:[a-zA-Z\d-]*!)?[\w\-%#;/?:@&=+$.~*'()]+)?/,
        a = '(?:' + n.source + '(?:[ \t]+' + t.source + ')?|' + t.source + '(?:[ \t]+' + n.source + ')?)',
        r = '(?:[^\\s\\x00-\\x08\\x0e-\\x1f!"#%&\'*,\\-:>?@[\\]`{|}\\x7f-\\x84\\x86-\\x9f\\ud800-\\udfff\\ufffe\\uffff]|[?:-]<PLAIN>)(?:[ \t]*(?:(?![#:])<PLAIN>|:<PLAIN>))*'.replace(/<PLAIN>/g, (function () {
          return '[^\\s\\x00-\\x08\\x0e-\\x1f,[\\]{}\\x7f-\\x84\\x86-\\x9f\\ud800-\\udfff\\ufffe\\uffff]'
        })),
        i = '"(?:[^"\\\\\r\n]|\\\\.)*"|\'(?:[^\'\\\\\r\n]|\\\\.)*\'';
        function o(e, t) {
          t = (t || '').replace(/m/g, '') + 'm';
          var n = '([:\\-,[{]\\s*(?:\\s<<prop>>[ \t]+)?)(?:<<value>>)(?=[ \t]*(?:$|,|\\]|\\}|(?:[\r\n]\\s*)?#))'.replace(/<<prop>>/g, (function () {
            return a
          })).replace(/<<value>>/g, (function () {
            return e
          }));
          return RegExp(n, t)
        }
        e.languages.yaml = {
          scalar: {
            pattern: RegExp('([\\-:]\\s*(?:\\s<<prop>>[ \t]+)?[|>])[ \t]*(?:((?:\r?\n|\r)[ \t]+)\\S[^\r\n]*(?:\\2[^\r\n]+)*)'.replace(/<<prop>>/g, (function () {
              return a
            }))),
            lookbehind: !0,
            alias: 'string'
          },
          comment: /#.*/,
          key: {
            pattern: RegExp('((?:^|[:\\-,[{\r\n?])[ \t]*(?:<<prop>>[ \t]+)?)<<key>>(?=\\s*:\\s)'.replace(/<<prop>>/g, (function () {
              return a
            })).replace(/<<key>>/g, (function () {
              return '(?:' + r + '|' + i + ')'
            }))),
            lookbehind: !0,
            greedy: !0,
            alias: 'atrule'
          },
          directive: {
            pattern: /(^[ \t]*)%.+/m,
            lookbehind: !0,
            alias: 'important'
          },
          datetime: {
            pattern: o('\\d{4}-\\d\\d?-\\d\\d?(?:[tT]|[ \t]+)\\d\\d?:\\d{2}:\\d{2}(?:\\.\\d*)?(?:[ \t]*(?:Z|[-+]\\d\\d?(?::\\d{2})?))?|\\d{4}-\\d{2}-\\d{2}|\\d\\d?:\\d{2}(?::\\d{2}(?:\\.\\d*)?)?'),
            lookbehind: !0,
            alias: 'number'
          },
          boolean: {
            pattern: o('true|false', 'i'),
            lookbehind: !0,
            alias: 'important'
          },
          null: {
            pattern: o('null|~', 'i'),
            lookbehind: !0,
            alias: 'important'
          },
          string: {
            pattern: o(i),
            lookbehind: !0,
            greedy: !0
          },
          number: {
            pattern: o('[+-]?(?:0x[\\da-f]+|0o[0-7]+|(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:e[+-]?\\d+)?|\\.inf|\\.nan)', 'i'),
            lookbehind: !0
          },
          tag: n,
          important: t,
          punctuation: /---|[:[\]{}\-,|>?]|\.\.\./
        },
        e.languages.yml = e.languages.yaml
      }(d),
      function () {
        if (void 0 !== d && 'undefined' != typeof document && document.querySelector) {
          var e,
          t = 'line-numbers',
          n = 'linkable-line-numbers',
          a = function () {
            if (void 0 === e) {
              var t = document.createElement('div');
              t.style.fontSize = '13px',
              t.style.lineHeight = '1.5',
              t.style.padding = '0',
              t.style.border = '0',
              t.innerHTML = '&nbsp;<br />&nbsp;',
              document.body.appendChild(t),
              e = 38 === t.offsetHeight,
              document.body.removeChild(t)
            }
            return e
          },
          r = !0,
          i = 0;
          d.hooks.add('before-sanity-check', (function (e) {
            var t = e.element.parentElement;
            if (u(t)) {
              var n = 0;
              o('.line-highlight', t).forEach((function (e) {
                n += e.textContent.length,
                e.parentNode.removeChild(e)
              })),
              n && /^(?: \n)+$/.test(e.code.slice( - n)) && (e.code = e.code.slice(0, - n))
            }
          })),
          d.hooks.add('complete', (function e(n) {
            var a = n.element.parentElement;
            if (u(a)) {
              clearTimeout(i);
              var r = d.plugins.lineNumbers,
              o = n.plugins && n.plugins.lineNumbers;
              s(a, t) && r && !o ? d.hooks.add('line-numbers', e) : (c(a) (), i = setTimeout(p, 1))
            }
          })),
          window.addEventListener('hashchange', p),
          window.addEventListener('resize', (function () {
            o('pre').filter(u).map((function (e) {
              return c(e)
            })).forEach(l)
          }))
        }
        function o(e, t) {
          return Array.prototype.slice.call((t || document).querySelectorAll(e))
        }
        function s(e, t) {
          return e.classList.contains(t)
        }
        function l(e) {
          e()
        }
        function u(e) {
          return !!(e && /pre/i.test(e.nodeName) && (e.hasAttribute('data-line') || e.id && d.util.isActive(e, n)))
        }
        function c(e, i, u) {
          var c = (i = 'string' == typeof i ? i : e.getAttribute('data-line') || '').replace(/\s+/g, '').split(',').filter(Boolean),
          p = + e.getAttribute('data-line-offset') || 0,
          g = (a() ? parseInt : parseFloat) (getComputedStyle(e).lineHeight),
          b = d.util.isActive(e, t),
          m = e.querySelector('code'),
          f = b ? e : m || e,
          h = [
          ],
          E = m && f != m ? function (e, t) {
            var n = getComputedStyle(e),
            a = getComputedStyle(t);
            function r(e) {
              return + e.substr(0, e.length - 2)
            }
            return t.offsetTop + r(a.borderTopWidth) + r(a.paddingTop) - r(n.paddingTop)
          }(e, m) : 0;
          c.forEach((function (t) {
            var n = t.split('-'),
            a = + n[0],
            r = + n[1] || a,
            i = e.querySelector('.line-highlight[data-range="' + t + '"]') || document.createElement('div');
            if (h.push((function () {
              i.setAttribute('aria-hidden', 'true'),
              i.setAttribute('data-range', t),
              i.className = (u || '') + ' line-highlight'
            })), b && d.plugins.lineNumbers) {
              var o = d.plugins.lineNumbers.getLine(e, a),
              s = d.plugins.lineNumbers.getLine(e, r);
              if (o) {
                var l = o.offsetTop + E + 'px';
                h.push((function () {
                  i.style.top = l
                }))
              }
              if (s) {
                var c = s.offsetTop - o.offsetTop + s.offsetHeight + 'px';
                h.push((function () {
                  i.style.height = c
                }))
              }
            } else h.push((function () {
              i.setAttribute('data-start', String(a)),
              a < r && i.setAttribute('data-end', String(r)),
              i.style.top = (a - p - 1) * g + E + 'px',
              i.textContent = new Array(r - a + 2).join(' \n')
            }));
            h.push((function () {
              i.style.width = e.scrollWidth + 'px'
            })),
            h.push((function () {
              f.appendChild(i)
            }))
          }));
          var _ = e.id;
          if (b && d.util.isActive(e, n) && _) {
            s(e, n) || h.push((function () {
              e.classList.add(n)
            }));
            var S = parseInt(e.getAttribute('data-start') || '1');
            o('.line-numbers-rows > span', e).forEach((function (e, t) {
              var n = t + S;
              e.onclick = function () {
                var e = _ + '.' + n;
                r = !1,
                location.hash = e,
                setTimeout((function () {
                  r = !0
                }), 1)
              }
            }))
          }
          return function () {
            h.forEach(l)
          }
        }
        function p() {
          var e = location.hash.slice(1);
          o('.temporary.line-highlight').forEach((function (e) {
            e.parentNode.removeChild(e)
          }));
          var t = (e.match(/\.([\d,-]+)$/) || [
            ,
            ''
          ]) [1];
          if (t && !document.getElementById(e)) {
            var n = e.slice(0, e.lastIndexOf('.')),
            a = document.getElementById(n);
            a && (a.hasAttribute('data-line') || a.setAttribute('data-line', ''), c(a, t, 'temporary ') (), r && document.querySelector('.temporary.line-highlight').scrollIntoView())
          }
        }
      }(),
      function () {
        if (void 0 !== d && 'undefined' != typeof document) {
          var e = 'line-numbers',
          t = /\n(?!$)/g,
          n = d.plugins.lineNumbers = {
            getLine: function (t, n) {
              if ('PRE' === t.tagName && t.classList.contains(e)) {
                var a = t.querySelector('.line-numbers-rows');
                if (a) {
                  var r = parseInt(t.getAttribute('data-start'), 10) || 1,
                  i = r + (a.children.length - 1);
                  n < r && (n = r),
                  i < n && (n = i);
                  var o = n - r;
                  return a.children[o]
                }
              }
            },
            resize: function (e) {
              r([e])
            },
            assumeViewportIndependence: !0
          },
          a = void 0;
          window.addEventListener('resize', (function () {
            n.assumeViewportIndependence && a === window.innerWidth || (a = window.innerWidth, r(Array.prototype.slice.call(document.querySelectorAll('pre.' + e))))
          })),
          d.hooks.add('complete', (function (n) {
            if (n.code) {
              var a = n.element,
              i = a.parentNode;
              if (i && /pre/i.test(i.nodeName) && !a.querySelector('.line-numbers-rows') && d.util.isActive(a, e)) {
                a.classList.remove(e),
                i.classList.add(e);
                var o,
                s = n.code.match(t),
                l = s ? s.length + 1 : 1,
                u = new Array(l + 1).join('<span></span>');
                (o = document.createElement('span')).setAttribute('aria-hidden', 'true'),
                o.className = 'line-numbers-rows',
                o.innerHTML = u,
                i.hasAttribute('data-start') && (i.style.counterReset = 'linenumber ' + (parseInt(i.getAttribute('data-start'), 10) - 1)),
                n.element.appendChild(o),
                r([i]),
                d.hooks.run('line-numbers', n)
              }
            }
          })),
          d.hooks.add('line-numbers', (function (e) {
            e.plugins = e.plugins || {
            },
            e.plugins.lineNumbers = !0
          }))
        }
        function r(e) {
          if (0 != (e = e.filter((function (e) {
            var t = function (e) {
              return e ? window.getComputedStyle ? getComputedStyle(e) : e.currentStyle || null : null
            }(e) ['white-space'];
            return 'pre-wrap' === t || 'pre-line' === t
          }))).length) {
            var n = e.map((function (e) {
              var n = e.querySelector('code'),
              a = e.querySelector('.line-numbers-rows');
              if (n && a) {
                var r = e.querySelector('.line-numbers-sizer'),
                i = n.textContent.split(t);
                r || ((r = document.createElement('span')).className = 'line-numbers-sizer', n.appendChild(r)),
                r.innerHTML = '0',
                r.style.display = 'block';
                var o = r.getBoundingClientRect().height;
                return r.innerHTML = '',
                {
                  element: e,
                  lines: i,
                  lineHeights: [
                  ],
                  oneLinerHeight: o,
                  sizer: r
                }
              }
            })).filter(Boolean);
            n.forEach((function (e) {
              var t = e.sizer,
              n = e.lines,
              a = e.lineHeights,
              r = e.oneLinerHeight;
              a[n.length - 1] = void 0,
              n.forEach((function (e, n) {
                if (e && 1 < e.length) {
                  var i = t.appendChild(document.createElement('span'));
                  i.style.display = 'block',
                  i.textContent = e
                } else a[n] = r
              }))
            })),
            n.forEach((function (e) {
              for (var t = e.sizer, n = e.lineHeights, a = 0, r = 0; r < n.length; r++) void 0 === n[r] && (n[r] = t.children[a++].getBoundingClientRect().height)
            })),
            n.forEach((function (e) {
              var t = e.sizer,
              n = e.element.querySelector('.line-numbers-rows');
              t.style.display = 'none',
              t.innerHTML = '',
              e.lineHeights.forEach((function (e, t) {
                n.children[t].style.height = e + 'px'
              }))
            }))
          }
        }
      }(),
      function () {
        if (void 0 !== d && 'undefined' != typeof document) {
          var e = [
          ];
          s((function (e) {
            if (e && e.meta && e.data) {
              if (e.meta.status && 400 <= e.meta.status) return 'Error: ' + (e.data.message || e.meta.status);
              if ('string' == typeof e.data.content) return 'function' == typeof atob ? atob(e.data.content.replace(/\s/g, '')) : 'Your browser cannot decode base64'
            }
            return null
          }), 'github'),
          s((function (e, t) {
            if (e && e.meta && e.data && e.data.files) {
              if (e.meta.status && 400 <= e.meta.status) return 'Error: ' + (e.data.message || e.meta.status);
              var n = e.data.files,
              a = t.getAttribute('data-filename');
              if (null == a) for (var r in n) if (n.hasOwnProperty(r)) {
                a = r;
                break
              }
              return void 0 !== n[a] ? n[a].content : 'Error: unknown or missing gist file ' + a
            }
            return null
          }), 'gist'),
          s((function (e) {
            return e && e.node && 'string' == typeof e.data ? e.data : null
          }), 'bitbucket');
          var t = 0,
          n = 'data-jsonp-status',
          a = 'loading',
          r = 'loaded',
          i = 'failed',
          o = 'pre[data-jsonp]:not([' + n + '="' + r + '"]):not([' + n + '="' + a + '"])';
          d.hooks.add('before-highlightall', (function (e) {
            e.selector += ', ' + o
          })),
          d.hooks.add('before-sanity-check', (function (s) {
            var l = s.element;
            if (l.matches(o)) {
              s.code = '',
              l.setAttribute(n, a);
              var u = l.appendChild(document.createElement('CODE'));
              u.textContent = 'Loading…';
              var c = s.language;
              u.className = 'language-' + c;
              var p = d.plugins.autoloader;
              p && p.loadLanguages(c);
              var g = l.getAttribute('data-adapter'),
              b = null;
              if (g) {
                if ('function' != typeof window[g]) return l.setAttribute(n, i),
                void (u.textContent = function (e) {
                  return '✖ Error: JSONP adapter function "' + e + '" doesn\'t exist'
                }(g));
                b = window[g]
              }
              var m = l.getAttribute('data-jsonp');
              !function (e, n, a, r) {
                var i = 'prismjsonp' + t++,
                o = document.createElement('a');
                o.href = e,
                o.href += (o.search ? '&' : '?') + (n || 'callback') + '=' + i;
                var s = document.createElement('script');
                s.src = o.href,
                s.onerror = function () {
                  u(),
                  r()
                };
                var l = setTimeout((function () {
                  u(),
                  r()
                }), d.plugins.jsonphighlight.timeout);
                function u() {
                  clearTimeout(l),
                  document.head.removeChild(s),
                  delete window[i]
                }
                window[i] = function (e) {
                  u(),
                  a(e)
                },
                document.head.appendChild(s)
              }(m, l.getAttribute('data-callback'), (function (t) {
                var a = null;
                if (b) a = b(t, l);
                 else for (var o = 0, s = e.length; o < s && null === (a = e[o].adapter(t, l)); o++);
                null === a ? (l.setAttribute(n, i), u.textContent = '✖ Error: Cannot parse response (perhaps you need an adapter function?)') : (l.setAttribute(n, r), u.textContent = a, d.highlightElement(u))
              }), (function () {
                l.setAttribute(n, i),
                u.textContent = function (e) {
                  return '✖ Error: Timeout loading ' + e
                }(m)
              }))
            }
          })),
          d.plugins.jsonphighlight = {
            timeout: 5000,
            registerAdapter: s,
            removeAdapter: function (t) {
              if ('string' == typeof t && (t = l(t)), 'function' == typeof t) {
                var n = e.findIndex((function (e) {
                  return e.adapter === t
                }));
                0 <= n && e.splice(n, 1)
              }
            },
            highlight: function (e) {
              for (var t, n = (e || document).querySelectorAll(o), a = 0; t = n[a++]; ) d.highlightElement(t)
            }
          }
        }
        function s(t, n) {
          n = n || t.name,
          'function' != typeof t || l(t) || l(n) || e.push({
            adapter: t,
            name: n
          })
        }
        function l(t) {
          if ('function' == typeof t) {
            for (var n = 0; a = e[n++]; ) if (a.adapter.valueOf() === t.valueOf()) return a.adapter
          } else if ('string' == typeof t) {
            var a;
            for (n = 0; a = e[n++]; ) if (a.name === t) return a.adapter
          }
          return null
        }
      }(),
      void 0 !== d && d.hooks.add('wrap', (function (e) {
        'keyword' === e.type && e.classes.push('keyword-' + e.content)
      })),
      function () {
        if (void 0 !== d && 'undefined' != typeof document) {
          var e = /(?:^|\s)command-line(?:\s|$)/,
          t = 'command-line-prompt',
          n = ''.startsWith ? function (e, t) {
            return e.startsWith(t)
          }
           : function (e, t) {
            return 0 === e.indexOf(t)
          };
          d.hooks.add('before-highlight', (function (a) {
            var i = r(a);
            if (!i.complete && a.code) {
              var o = a.element.parentElement;
              if (o && /pre/i.test(o.nodeName) && (e.test(o.className) || e.test(a.element.className))) {
                var s = a.element.querySelector('.' + t);
                s && s.remove();
                var l = a.code.split('\n');
                i.numberOfLines = l.length;
                var d = i.outputLines = [
                ],
                u = o.getAttribute('data-output'),
                c = o.getAttribute('data-filter-output');
                if (null !== u) u.split(',').forEach((function (e) {
                  var t = e.split('-'),
                  n = parseInt(t[0], 10),
                  a = 2 === t.length ? parseInt(t[1], 10) : n;
                  if (!isNaN(n) && !isNaN(a)) {
                    n < 1 && (n = 1),
                    a > l.length && (a = l.length),
                    a--;
                    for (var r = --n; r <= a; r++) d[r] = l[r],
                    l[r] = ''
                  }
                }));
                 else if (c) for (var p = 0; p < l.length; p++) n(l[p], c) && (d[p] = l[p].slice(c.length), l[p] = '');
                a.code = l.join('\n')
              } else i.complete = !0
            } else i.complete = !0
          })),
          d.hooks.add('before-insert', (function (e) {
            var t = r(e);
            if (!t.complete) {
              for (var n = e.highlightedCode.split('\n'), a = t.outputLines || [
              ], i = 0, o = a.length; i < o; i++) a.hasOwnProperty(i) && (n[i] = a[i]);
              e.highlightedCode = n.join('\n')
            }
          })),
          d.hooks.add('complete', (function (n) {
            if (function (e) {
              return 'command-line' in (e.vars = e.vars || {
              })
            }(n)) {
              var i = r(n);
              if (!i.complete) {
                var o,
                s = n.element.parentElement;
                e.test(n.element.className) && (n.element.className = n.element.className.replace(e, ' ')),
                e.test(s.className) || (s.className += ' command-line');
                var l = i.numberOfLines || 0,
                d = m('data-prompt', '');
                o = a('' !== d ? '<span data-prompt="' + d + '"></span>' : '<span data-user="' + m('data-user', 'user') + '" data-host="' + m('data-host', 'localhost') + '"></span>', l);
                var u = document.createElement('span');
                u.className = t,
                u.innerHTML = o;
                for (var c = i.outputLines || [
                ], p = 0, g = c.length; p < g; p++) if (c.hasOwnProperty(p)) {
                  var b = u.children[p];
                  b.removeAttribute('data-user'),
                  b.removeAttribute('data-host'),
                  b.removeAttribute('data-prompt')
                }
                n.element.insertBefore(u, n.element.firstChild),
                i.complete = !0
              }
            }
            function m(e, t) {
              return (s.getAttribute(e) || t).replace(/"/g, '&quot')
            }
          }))
        }
        function a(e, t) {
          for (var n = '', a = 0; a < t; a++) n += e;
          return n
        }
        function r(e) {
          var t = e.vars = e.vars || {
          };
          return t['command-line'] = t['command-line'] || {
          }
        }
      }(),
      function () {
        if (void 0 !== d && 'undefined' != typeof document) {
          var e = [
          ],
          t = {
          },
          n = function () {
          };
          d.plugins.toolbar = {
          };
          var a = d.plugins.toolbar.registerButton = function (n, a) {
            var r;
            r = 'function' == typeof a ? a : function (e) {
              var t;
              return 'function' == typeof a.onClick ? ((t = document.createElement('button')).type = 'button', t.addEventListener('click', (function () {
                a.onClick.call(this, e)
              }))) : 'string' == typeof a.url ? (t = document.createElement('a')).href = a.url : t = document.createElement('span'),
              a.className && t.classList.add(a.className),
              t.textContent = a.text,
              t
            },
            n in t ? console.warn('There is a button with the key "' + n + '" registered already.') : e.push(t[n] = r)
          },
          r = d.plugins.toolbar.hook = function (a) {
            var r = a.element.parentNode;
            if (r && /pre/i.test(r.nodeName) && !r.parentNode.classList.contains('code-toolbar')) {
              var i = document.createElement('div');
              i.classList.add('code-toolbar'),
              r.parentNode.insertBefore(i, r),
              i.appendChild(r);
              var o = document.createElement('div');
              o.classList.add('toolbar');
              var s = e,
              l = function (e) {
                for (; e; ) {
                  var t = e.getAttribute('data-toolbar-order');
                  if (null != t) return (t = t.trim()).length ? t.split(/\s*,\s*/g) : [
                  ];
                  e = e.parentElement
                }
              }(a.element);
              l && (s = l.map((function (e) {
                return t[e] || n
              }))),
              s.forEach((function (e) {
                var t = e(a);
                if (t) {
                  var n = document.createElement('div');
                  n.classList.add('toolbar-item'),
                  n.appendChild(t),
                  o.appendChild(n)
                }
              })),
              i.appendChild(o)
            }
          };
          a('label', (function (e) {
            var t = e.element.parentNode;
            if (t && /pre/i.test(t.nodeName) && t.hasAttribute('data-label')) {
              var n,
              a,
              r = t.getAttribute('data-label');
              try {
                a = document.querySelector('template#' + r)
              } catch (e) {
              }
              return a ? n = a.content : (t.hasAttribute('data-url') ? (n = document.createElement('a')).href = t.getAttribute('data-url') : n = document.createElement('span'), n.textContent = r),
              n
            }
          })),
          d.hooks.add('complete', r)
        }
      }(),
      function () {
        function e(e, n) {
          e.addEventListener('click', (function () {
            !function (e) {
              navigator.clipboard ? navigator.clipboard.writeText(e.getText()).then(e.success, (function () {
                t(e)
              })) : t(e)
            }(n)
          }))
        }
        function t(e) {
          var t = document.createElement('textarea');
          t.value = e.getText(),
          t.style.top = '0',
          t.style.left = '0',
          t.style.position = 'fixed',
          document.body.appendChild(t),
          t.focus(),
          t.select();
          try {
            var n = document.execCommand('copy');
            setTimeout((function () {
              n ? e.success() : e.error()
            }), 1)
          } catch (t) {
            setTimeout((function () {
              e.error(t)
            }), 1)
          }
          document.body.removeChild(t)
        }
        void 0 !== d && 'undefined' != typeof document && (d.plugins.toolbar ? d.plugins.toolbar.registerButton('copy-to-clipboard', (function (t) {
          var n = t.element,
          a = function (e) {
            var t = {
              copy: 'Copy',
              'copy-error': 'Press Ctrl+C to copy',
              'copy-success': 'Copied!',
              'copy-timeout': 5000
            };
            for (var n in t) {
              for (var a = 'data-prismjs-' + n, r = e; r && !r.hasAttribute(a); ) r = r.parentElement;
              r && (t[n] = r.getAttribute(a))
            }
            return t
          }(n),
          r = document.createElement('button');
          r.className = 'copy-to-clipboard-button',
          r.setAttribute('type', 'button');
          var i = document.createElement('span');
          return r.appendChild(i),
          s('copy'),
          e(r, {
            getText: function () {
              return n.textContent
            },
            success: function () {
              s('copy-success'),
              o()
            },
            error: function () {
              s('copy-error'),
              setTimeout((function () {
                !function (e) {
                  window.getSelection().selectAllChildren(e)
                }(n)
              }), 1),
              o()
            }
          }),
          r;
          function o() {
            setTimeout((function () {
              s('copy')
            }), a['copy-timeout'])
          }
          function s(e) {
            i.textContent = a[e],
            r.setAttribute('data-copy-state', e)
          }
        })) : console.warn('Copy to Clipboard plugin loaded before Toolbar plugin.'))
      }()
    }
  },
  t = {
  };
  function n(a) {
    var r = t[a];
    if (void 0 !== r) return r.exports;
    var i = t[a] = {
      exports: {
      }
    };
    return e[a](i, i.exports, n),
    i.exports
  }
  n.g = function () {
    if ('object' == typeof globalThis) return globalThis;
    try {
      return this || new Function('return this') ()
    } catch (e) {
      if ('object' == typeof window) return window
    }
  }();
  n(213)
}();
