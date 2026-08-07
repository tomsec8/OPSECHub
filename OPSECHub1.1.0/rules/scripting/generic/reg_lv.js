/*******************************************************************************

    uBlock Origin Lite - a comprehensive, MV3-compliant content blocker
    Copyright (C) 2014-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock
*/

// reg_lv

// Important!
// Isolate from global scope
(function uBOL_cssGenericImport() {

const lowlyGeneric = new Map(undefined);
const highlyGeneric = "a[href=\"http://www.salidzini.lv/\"][style=\"display: block; width: 120px; height: 40px; overflow: hidden; position: relative;\"],\na[href=\"http://www.salidzini.lv/\"][style=\"display: block; width: 88px; height: 31px; overflow: hidden; position: relative;\"]";
const exceptions = [".article-ad-placeholder\n.dfp-ad",".article-ad-placeholder\n.dfp-ad","#ad_table\n.single_ad",".adocean"];
const hostnames = ["tvnet.lv","apollo.lv","varianti.lv","atverskapi.delfi.lv"];
const hasEntities = false;

self.genericSelectorMaps = self.genericSelectorMaps ?? [];
self.genericSelectorMaps.push(lowlyGeneric);
self.genericDetails = self.genericDetails ?? [];
self.genericDetails.push({ highlyGeneric, exceptions, hostnames, hasEntities });

})();

/******************************************************************************/
